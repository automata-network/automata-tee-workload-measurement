//! SessionRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum, ProviderEx};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use tracing::info;

use crate::base_image_registry::BaseImageRegistry;
use crate::stubs::SessionRegistry::{CVMSession, SessionRegistryEvents, SessionRegistryInstance};
use crate::stubs::{
    AmdSevSnpZkEvidence, AttestationEvidence, IntelTdxDcapZkEvidence, ProgramBoundZkProof,
    PublicIdentity, SessionKeyRotationEvidence, SessionRenewalAuthorization, TeeReport,
    TpmQuoteEvidence, TpmQuoteJournalV1, TpmReport, op_expires_at, sign_message,
};
use crate::types::{AppRef, LifecycleSessionResponse, RegisterSessionResponse, RotateKeyResponse};
use crate::workload_registry::WorkloadRegistry;

pub struct SessionRegistry {
    stub: SessionRegistryInstance<NetworkProvider>,
}

impl SessionRegistry {
    pub fn new(contract: Address, p: NetworkProvider) -> Self {
        Self {
            stub: SessionRegistryInstance::new(contract, p),
        }
    }

    pub async fn workload_registry(&self) -> Result<WorkloadRegistry> {
        let addr = self.stub.workloadRegistry().call().await?;
        Ok(WorkloadRegistry::new(addr, self.stub.provider().clone()))
    }

    pub async fn base_image_registry(&self) -> Result<BaseImageRegistry> {
        let addr = self.stub.baseImageRegistry().call().await?;
        Ok(BaseImageRegistry::new(addr, self.stub.provider().clone()))
    }

    /// Query the nonce for a given owner fingerprint.
    ///
    /// The nonce is used in TPM quote extraData binding to prevent replay attacks.
    pub async fn get_nonce(&self, owner_fingerprint: B256) -> Result<U256> {
        let nonce = self
            .stub
            .getNonce(owner_fingerprint)
            .call()
            .await
            .context("Failed to call getNonce")?;
        Ok(nonce)
    }

    /// Register a session to the SessionRegistry contract.
    ///
    /// This function:
    /// 1. Pre-computes the sessionId from the attestation evidence
    /// 2. Builds the signature message matching the contract's expected format
    /// 3. Signs the message with the provided private key
    /// 4. Submits the transaction and waits for confirmation
    /// 5. Returns the sessionId from the emitted event
    pub async fn register_session(
        &self,
        signer: &PrivateKeySigner,
        evidence: AttestationEvidence,
        workload_ref: AppRef,
        base_image_ref: AppRef,
        platform_profile_id: B256,
        variant_id: B256,
        op_expiry_seconds: u64,
    ) -> Result<RegisterSessionResponse> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let op_expires_at = op_expires_at(op_expiry_seconds);

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();
        let session_id =
            compute_session_id_from_parts(&evidence.tpm_quote_report, &evidence.tee_report)?;
        let workload_id = WorkloadRegistry::get_workload_id(&workload_ref);
        let base_image_id = BaseImageRegistry::get_image_id(&base_image_ref);
        // sessionKeyFingerprint = LibKey.computeKeyFingerprint(evidence.sessionKey); the contract
        // derives it internally and folds it into the owner-signature digest (see below).
        let session_key_fingerprint = evidence.session_key.fingerprint();

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            op_expires_at = op_expires_at,
            "Submitting registerSession transaction"
        );

        // Build and sign the owner message. Must match SessionRegistry.registerSession exactly:
        // sha256(abi.encode(SESSION_REGISTER_MSG, chainId, address(this), opExpiresAt, sessionId,
        //                   workloadId, baseImageId, platformProfileId, variantId, sessionKeyFingerprint))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(op_expires_at),
                session_id,
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                session_key_fingerprint,
            ),
            signer,
        )
        .await?;

        let response = self
            .register_session_presigned(
                evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                op_expires_at,
                owner_identity.into(),
                sig_bytes,
            )
            .await?;

        Ok(response)
    }

    /// Rotate a session to a new session key.
    ///
    /// This function:
    /// 1. Pre-computes the newSessionId from the rotation evidence
    /// 2. Builds the signature message matching the contract's expected format
    /// 3. Signs the message with the provided private key
    /// 4. Submits the transaction and waits for confirmation
    /// 5. Returns the newSessionId from the emitted event
    pub async fn rotate_key(
        &self,
        signer: &PrivateKeySigner,
        old_session_id: B256,
        tee_report_bytes_hash: B256,
        rotation_evidence: SessionKeyRotationEvidence,
        op_expiry_seconds: u64,
    ) -> Result<RotateKeyResponse> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let op_expires_at = op_expires_at(op_expiry_seconds);

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();

        // Pre-compute newSessionId
        let new_session_id =
            compute_new_session_id(tee_report_bytes_hash, &rotation_evidence.tpm_quote_report)?;

        info!(
            address = %self.stub.address(),
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            op_expires_at = op_expires_at,
            "Submitting rotateKey transaction"
        );

        // Build and sign the message
        // Message: sha256(abi.encode(SESSION_ROTATE_KEY_MSG, chainId, contractAddr, opExpiresAt, oldSessionId, newSessionId))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_ROTATE_KEY_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(op_expires_at),
                old_session_id,
                new_session_id,
            ),
            signer,
        )
        .await?;

        let response = self
            .rotate_key_presigned(
                old_session_id,
                tee_report_bytes_hash,
                rotation_evidence,
                op_expires_at,
                owner_identity,
                sig_bytes,
            )
            .await?;

        Ok(response)
    }

    /// Register a session with a pre-signed owner signature.
    ///
    /// This is used by relay services that cannot sign on behalf of the owner.
    /// The owner must sign the registration message externally.
    ///
    /// Returns (session_id, tx_hash).
    pub async fn register_session_presigned(
        &self,
        evidence: AttestationEvidence,
        workload_id: B256,
        base_image_id: B256,
        platform_profile_id: B256,
        variant_id: B256,
        op_expires_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<RegisterSessionResponse> {
        let session_id =
            compute_session_id_from_parts(&evidence.tpm_quote_report, &evidence.tee_report)?;

        let contract_evidence = evidence.try_into()?;

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            op_expires_at = op_expires_at,
            "Submitting registerSession (presigned)"
        );

        // Call the contract
        let pending = self
            .stub
            .registerSession(
                contract_evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                op_expires_at,
                owner_identity.into(),
                owner_signature,
            )
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();
        info!(tx_hash = %tx_hash, "Transaction submitted");

        let mut tx = PendingTxAccum::new(pending, |event, result: &mut RegisterSessionResponse| {
            if let SessionRegistryEvents::SessionRegistered(msg) = event {
                result.session_id = msg.sessionId
            }
        });

        let mut response = tx
            .result()
            .await
            .context("Failed to get transaction receipt")?;

        response.tx_hash = tx.tx_hash();

        Ok(response)
    }

    /// Rotate a session with a pre-signed owner signature.
    ///
    /// This is used by relay services that cannot sign on behalf of the owner.
    /// The owner must sign the rotation message externally.
    ///
    /// Returns (new_session_id, tx_hash).
    pub async fn rotate_key_presigned(
        &self,
        old_session_id: B256,
        tee_report_bytes_hash: B256,
        rotation_evidence: SessionKeyRotationEvidence,
        op_expires_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<RotateKeyResponse> {
        // Pre-compute newSessionId
        let new_session_id =
            compute_new_session_id(tee_report_bytes_hash, &rotation_evidence.tpm_quote_report)?;

        info!(
            address = %self.stub.address(),
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            op_expires_at = op_expires_at,
            "Submitting rotateKey (presigned)"
        );

        let contract_rotation_evidence = rotation_evidence.try_into()?;

        // Call the contract
        let pending = self
            .stub
            .rotateKey(
                old_session_id,
                tee_report_bytes_hash,
                contract_rotation_evidence,
                op_expires_at,
                owner_identity.into(),
                owner_signature,
            )
            .send_ex()
            .await?;

        info!(tx_hash = %pending.tx_hash(), "Rotation transaction submitted");

        let mut tx = PendingTxAccum::new(pending, |event, result: &mut RotateKeyResponse| {
            if let SessionRegistryEvents::SessionKeyRotated(msg) = event {
                result.new_session_id = msg.newSessionId;
            }
        });

        let mut response = tx
            .result()
            .await
            .context("Failed to get rotation transaction receipt")?;

        response.tx_hash = tx.tx_hash();

        Ok(response)
    }

    /// Submit a fully attested renewal with caller-supplied predecessor and
    /// owner authorizations.
    #[allow(clippy::too_many_arguments)]
    pub async fn renew_session_presigned(
        &self,
        old_session_id: B256,
        new_evidence: AttestationEvidence,
        workload_id: B256,
        base_image_id: B256,
        platform_profile_id: B256,
        measurement_variant_id: B256,
        renewal_authorization: SessionRenewalAuthorization,
        op_expires_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<LifecycleSessionResponse> {
        let contract_evidence = new_evidence.try_into()?;

        let pending = self
            .stub
            .renewSession(
                old_session_id,
                contract_evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                measurement_variant_id,
                renewal_authorization.into(),
                op_expires_at,
                owner_identity.into(),
                owner_signature,
            )
            .send_ex()
            .await?;

        let mut tx =
            PendingTxAccum::new(pending, |event, result: &mut LifecycleSessionResponse| {
                if let SessionRegistryEvents::SessionRenewed(message) = event {
                    result.new_session_id = message.newSessionId;
                }
            });
        let mut response = tx.result().await.context("Failed to get renewal receipt")?;
        response.tx_hash = tx.tx_hash();
        Ok(response)
    }

    /// Submit a fully attested recovery with caller-supplied owner
    /// authorization. No predecessor TPM key is required.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_session_presigned(
        &self,
        old_session_id: B256,
        new_evidence: AttestationEvidence,
        workload_id: B256,
        base_image_id: B256,
        platform_profile_id: B256,
        measurement_variant_id: B256,
        op_expires_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<LifecycleSessionResponse> {
        let contract_evidence = new_evidence.try_into()?;

        let pending = self
            .stub
            .recoverSession(
                old_session_id,
                contract_evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                measurement_variant_id,
                op_expires_at,
                owner_identity.into(),
                owner_signature,
            )
            .send_ex()
            .await?;

        let mut tx =
            PendingTxAccum::new(pending, |event, result: &mut LifecycleSessionResponse| {
                if let SessionRegistryEvents::SessionRecovered(message) = event {
                    result.new_session_id = message.newSessionId;
                }
            });
        let mut response = tx
            .result()
            .await
            .context("Failed to get recovery receipt")?;
        response.tx_hash = tx.tx_hash();
        Ok(response)
    }

    /// Revoke a session in the SessionRegistry contract.
    pub async fn revoke_session(
        &self,
        signer: &PrivateKeySigner,
        session_id: B256,
        op_expiry_seconds: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let op_expires_at = op_expires_at(op_expiry_seconds);

        let chain_id = self.stub.provider().chain_id();

        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_REVOKE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(op_expires_at),
                session_id,
            ),
            signer,
        )
        .await?;

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            op_expires_at = op_expires_at,
            "Submitting revokeSession transaction"
        );

        let pending = self
            .stub
            .revokeSession(session_id, op_expires_at, owner_identity.into(), sig_bytes)
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();
        info!(tx_hash = %tx_hash, "Revocation transaction submitted");

        let mut tx = PendingTxAccum::new(pending, move |event, found: &mut bool| {
            if let SessionRegistryEvents::SessionRevoked(msg) = event {
                if msg.sessionId == session_id {
                    *found = true;
                }
            }
        });

        let found = tx
            .result()
            .await
            .context("Failed to get revocation receipt")?;

        anyhow::ensure!(
            found,
            "No SessionRevoked event with expected sessionId {session_id}"
        );

        Ok(tx.tx_hash())
    }

    /// Get the full session data.
    pub async fn get_session(&self, session_id: B256) -> Result<CVMSession> {
        let session = self.stub.getSession(session_id).call_ex().await?;
        Ok(session)
    }

    /// Get session ID by session fingerprint.
    pub async fn get_session_id(&self, session_fingerprint: B256) -> Result<B256> {
        let session_id = self
            .stub
            .getSessionId(session_fingerprint)
            .call_ex()
            .await?;
        Ok(session_id)
    }

    /// Get the owner fingerprint of a session.
    pub async fn get_session_owner(&self, session_id: B256) -> Result<B256> {
        let owner = self.stub.getSessionOwner(session_id).call_ex().await?;
        Ok(owner)
    }

    /// Check if a session is active (exists, not revoked, not expired).
    pub async fn is_session_active(&self, session_id: B256) -> Result<bool> {
        let active = self.stub.isSessionActive(session_id).call_ex().await?;
        Ok(active)
    }

    /// Check if a session has expired.
    pub async fn is_session_expired(&self, session_id: B256) -> Result<bool> {
        let expired = self.stub.isSessionExpired(session_id).call_ex().await?;
        Ok(expired)
    }
}

/// Compute the exact `teeReportBytesHash` stored by `SessionRegistry`.
pub fn compute_tee_report_hash(tee_report: &TeeReport) -> Result<B256> {
    match tee_report.tee_type {
        0 => {
            let full_quote_hash = match tee_report.verification_backend_type {
                0 => keccak256(&tee_report.data),
                1 | 2 => {
                    let evidence = IntelTdxDcapZkEvidence::abi_decode(&tee_report.data).context(
                        "Failed to decode IntelTdxDcapZkEvidence from Intel TDX TeeReport.data",
                    )?;
                    verify_and_extract_intel_tdx_full_quote_hash(&evidence)?
                }
                value => {
                    anyhow::bail!("Invalid VerificationBackendType value for Intel TDX: {value}")
                }
            };
            Ok(full_quote_hash)
        }
        1 => {
            if tee_report.verification_backend_type == 0 {
                anyhow::bail!("AMD SEV-SNP does not support VerificationBackendType.Solidity");
            }
            let evidence = AmdSevSnpZkEvidence::abi_decode(&tee_report.data)
                .context("Failed to decode AmdSevSnpZkEvidence from AMD SEV-SNP TeeReport.data")?;
            anyhow::ensure!(
                evidence.rawReport.len() == 1184,
                "AmdSevSnpZkEvidence.rawReport must be 1184 bytes, got {}",
                evidence.rawReport.len()
            );
            Ok(keccak256(evidence.rawReport))
        }
        value => anyhow::bail!("Invalid TEEType value: {value}"),
    }
}

fn verify_and_extract_intel_tdx_full_quote_hash(evidence: &IntelTdxDcapZkEvidence) -> Result<B256> {
    const JOURNAL_LENGTH: usize = 333;
    const COMPACT_OUTPUT_V1_LENGTH: usize = 131;
    const COMPACT_OUTPUT_FORMAT_GUARD_OFFSET: usize = 13;
    const COMPACT_OUTPUT_MAGIC_OFFSET: usize = 29;
    const COMPACT_OUTPUT_TYPE_OFFSET: usize = 33;
    const COMPACT_OUTPUT_VERSION_OFFSET: usize = 35;
    const COMPACT_OUTPUT_FULL_QUOTE_HASH_OFFSET: usize = 37;
    const COMPACT_OUTPUT_QUOTE_BODY_HASH_OFFSET: usize = 69;

    let output = evidence.proof.output.as_ref();
    anyhow::ensure!(
        output.len() == JOURNAL_LENGTH,
        "Intel TDX DCAP journal must be {JOURNAL_LENGTH} bytes, got {}",
        output.len()
    );
    let compact_output_length = u16::from_be_bytes([output[0], output[1]]) as usize;
    anyhow::ensure!(
        compact_output_length == COMPACT_OUTPUT_V1_LENGTH,
        "Intel TDX DCAP compact output must be {COMPACT_OUTPUT_V1_LENGTH} bytes, got {compact_output_length}"
    );
    anyhow::ensure!(
        output[COMPACT_OUTPUT_FORMAT_GUARD_OFFSET..COMPACT_OUTPUT_MAGIC_OFFSET] == [0; 16],
        "Intel TDX DCAP compact output format guard must be zero"
    );
    anyhow::ensure!(
        output[COMPACT_OUTPUT_MAGIC_OFFSET..COMPACT_OUTPUT_TYPE_OFFSET] == *b"ATKJ",
        "Intel TDX DCAP compact output magic must be ATKJ"
    );
    let format_type = u16::from_be_bytes([
        output[COMPACT_OUTPUT_TYPE_OFFSET],
        output[COMPACT_OUTPUT_TYPE_OFFSET + 1],
    ]);
    anyhow::ensure!(
        format_type == 1,
        "Intel TDX DCAP compact output type must be 1, got {format_type}"
    );
    let format_version = u16::from_be_bytes([
        output[COMPACT_OUTPUT_VERSION_OFFSET],
        output[COMPACT_OUTPUT_VERSION_OFFSET + 1],
    ]);
    anyhow::ensure!(
        format_version == 1,
        "Intel TDX DCAP compact output version must be 1, got {format_version}"
    );
    let body_type = u16::from_be_bytes([output[4], output[5]]);
    let body_len = dcap_body_len(body_type)?;
    anyhow::ensure!(
        evidence.quoteBody.len() == body_len,
        "Intel TDX quote body type {body_type} requires {body_len} bytes, got {}",
        evidence.quoteBody.len()
    );
    let committed_body_hash = B256::from_slice(
        &output[COMPACT_OUTPUT_QUOTE_BODY_HASH_OFFSET..COMPACT_OUTPUT_QUOTE_BODY_HASH_OFFSET + 32],
    );
    let supplied_body_hash = keccak256(&evidence.quoteBody);
    anyhow::ensure!(
        supplied_body_hash == committed_body_hash,
        "Intel TDX quote body hash does not match the ZK journal"
    );
    Ok(B256::from_slice(
        &output[COMPACT_OUTPUT_FULL_QUOTE_HASH_OFFSET..COMPACT_OUTPUT_FULL_QUOTE_HASH_OFFSET + 32],
    ))
}

fn dcap_body_len(body_type: u16) -> Result<usize> {
    match body_type {
        2 => Ok(584),
        3 => Ok(648),
        value => anyhow::bail!("Unsupported Intel TDX DCAP quote body type: {value}"),
    }
}

fn compute_tpm_signature_hash(tpm_quote_report: &TpmReport) -> Result<B256> {
    anyhow::ensure!(
        tpm_quote_report.tpm_report_type == 0,
        "Expected TpmReportType.TpmQuote, got {}",
        tpm_quote_report.tpm_report_type
    );
    match tpm_quote_report.verification_backend_type {
        0 => {
            let evidence = TpmQuoteEvidence::abi_decode(&tpm_quote_report.data)
                .context("Failed to decode TpmQuoteEvidence")?;
            Ok(keccak256(evidence.tpmSignature))
        }
        2 => {
            let proof = ProgramBoundZkProof::abi_decode(&tpm_quote_report.data)
                .context("Failed to decode ProgramBoundZkProof from TpmReport.data")?;
            let journal = TpmQuoteJournalV1::abi_decode(&proof.output)
                .context("Failed to decode TpmQuoteJournalV1 from ProgramBoundZkProof.output")?;
            Ok(journal.tpmSignatureHash)
        }
        value => anyhow::bail!("Unsupported TPM Quote VerificationBackendType value: {value}"),
    }
}

/// Compute sessionId from the raw TPM quote report data and the TEE report.
///
/// This is useful when you have the raw bytes directly. `tee_report` is taken whole (not
/// just its `data`) because the report hash is backend-dependent — see
/// [`compute_tee_report_hash`].
pub fn compute_session_id_from_parts(
    tpm_quote_report: &TpmReport,
    tee_report: &TeeReport,
) -> Result<B256> {
    let tee_report_bytes_hash = compute_tee_report_hash(tee_report)?;
    let tpm_signature_hash = compute_tpm_signature_hash(tpm_quote_report)?;

    // 3. Compute sessionId: keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))
    let session_domain = keccak256(b"CVM_SESSION_V1");
    let session_id =
        keccak256((session_domain, tpm_signature_hash, tee_report_bytes_hash).abi_encode_params());

    Ok(session_id)
}

/// Compute the new session identifier for rotation.
pub fn compute_new_session_id(
    tee_report_bytes_hash: B256,
    tpm_quote_report: &TpmReport,
) -> Result<B256> {
    let new_tpm_signature_hash = compute_tpm_signature_hash(tpm_quote_report)?;

    // Compute newSessionId: keccak256(abi.encode(SESSION_DOMAIN, newTpmSignatureHash, teeReportBytesHash))
    let session_domain = keccak256(b"CVM_SESSION_V1");
    let new_session_id = keccak256(
        (
            session_domain,
            new_tpm_signature_hash,
            tee_report_bytes_hash,
        )
            .abi_encode_params(),
    );

    Ok(new_session_id)
}

#[cfg(test)]
mod tests {
    use super::{compute_new_session_id, compute_tee_report_hash};
    use crate::stubs::{
        AmdSevSnpZkEvidence, IntelTdxDcapZkEvidence, ProgramBoundZkProof, TeeReport,
        TpmQuoteEvidence, TpmQuoteJournalV1, TpmReport,
    };
    use alloy::primitives::{B256, Bytes, keccak256};
    use alloy::sol_types::SolValue;

    #[test]
    fn amd_sev_snp_hashes_the_exact_raw_report() {
        let raw_report = Bytes::from(vec![0xabu8; 1184]);
        let data: Bytes = AmdSevSnpZkEvidence {
            proof: ProgramBoundZkProof {
                programIdentifier: B256::repeat_byte(0x11),
                output: Bytes::from(vec![0x22; 32]),
                proofBytes: Bytes::from(vec![0x33; 64]),
            },
            rawReport: raw_report.clone(),
        }
        .abi_encode()
        .into();
        let report = TeeReport {
            verification_backend_type: 2,
            tee_type: 1,
            data,
        };
        assert_eq!(
            compute_tee_report_hash(&report).unwrap(),
            keccak256(raw_report)
        );
    }

    #[test]
    fn intel_tdx_solidity_and_zk_hash_the_same_complete_raw_quote() {
        let quote_body = vec![0x44u8; 584];
        let mut full_quote = vec![0u8; 48];
        full_quote[0..2].copy_from_slice(&4u16.to_le_bytes());
        full_quote.extend_from_slice(&quote_body);
        full_quote.extend_from_slice(&[0x77; 64]);
        let full_quote_hash = keccak256(&full_quote);

        let mut output = Vec::with_capacity(333);
        output.extend_from_slice(&131u16.to_be_bytes());
        output.extend_from_slice(&4u16.to_be_bytes());
        output.extend_from_slice(&2u16.to_be_bytes());
        output.push(0);
        output.extend_from_slice(&[0x11; 6]);
        output.extend_from_slice(&[0; 16]);
        output.extend_from_slice(b"ATKJ");
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(full_quote_hash.as_slice());
        output.extend_from_slice(keccak256(&quote_body).as_slice());
        output.extend_from_slice(&[0x99; 32]);
        output.extend_from_slice(&[0u8; 8 + 6 * 32]);
        let data: Bytes = IntelTdxDcapZkEvidence {
            proof: ProgramBoundZkProof {
                programIdentifier: B256::repeat_byte(0x55),
                output: output.into(),
                proofBytes: Bytes::from(vec![0x66; 64]),
            },
            quoteBody: quote_body.into(),
        }
        .abi_encode()
        .into();
        let zk_report = TeeReport {
            verification_backend_type: 2,
            tee_type: 0,
            data,
        };
        let solidity_report = TeeReport {
            verification_backend_type: 0,
            tee_type: 0,
            data: full_quote.into(),
        };
        assert_eq!(
            compute_tee_report_hash(&zk_report).unwrap(),
            full_quote_hash
        );
        assert_eq!(
            compute_tee_report_hash(&solidity_report).unwrap(),
            full_quote_hash
        );
    }

    #[test]
    fn raw_tpm_quote_and_zk_tpm_quote_use_the_current_evidence_formats() {
        let signature = Bytes::from(vec![0x77u8; 64]);
        let raw_data: Bytes = TpmQuoteEvidence {
            tpmsAttest: Bytes::from(vec![0x88; 32]),
            tpmSignature: signature.clone(),
            pcr0StartupLocality: 0xff,
            pcrValues256: Vec::new(),
            pcrValues384: Vec::new(),
        }
        .abi_encode()
        .into();
        let raw_report = TpmReport {
            verification_backend_type: 0,
            tpm_report_type: 0,
            data: raw_data,
        };
        let tee_hash = B256::repeat_byte(0x99);
        let raw_session_id = compute_new_session_id(tee_hash, &raw_report).unwrap();

        let signature_hash = keccak256(signature);
        let journal = TpmQuoteJournalV1 {
            akPubFingerprint: B256::ZERO,
            qualifyingData: B256::ZERO,
            tpmSignatureHash: signature_hash,
            pcrCommitment: crate::stubs::PcrCommitment {
                pcrSelect: B256::ZERO,
                pcrDigest: B256::ZERO,
            },
            policyCommitment: B256::ZERO,
        };
        let zk_data: Bytes = ProgramBoundZkProof {
            programIdentifier: B256::repeat_byte(0xaa),
            output: journal.abi_encode().into(),
            proofBytes: Bytes::from(vec![0xbb; 64]),
        }
        .abi_encode()
        .into();
        let zk_report = TpmReport {
            verification_backend_type: 2,
            tpm_report_type: 0,
            data: zk_data,
        };
        assert_eq!(
            raw_session_id,
            compute_new_session_id(tee_hash, &zk_report).unwrap()
        );
    }
}
