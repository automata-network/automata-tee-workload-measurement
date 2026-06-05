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
    AttestationEvidence, PublicIdentity, SessionRotationEvidence, TeeReport, TpmQuoteReport,
    ZkProof, expire_at, sign_message,
};
use crate::types::{AppRef, RegisterSessionResponse, RotateSessionResponse};
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
        expire_offset_secs: u64,
    ) -> Result<RegisterSessionResponse> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let expire_at = expire_at(expire_offset_secs);

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();
        let session_id =
            compute_session_id_from_parts(&evidence.tpm_quote_report.data, &evidence.tee_report)?;
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
            expire_at = expire_at,
            "Submitting registerSession transaction"
        );

        // Build and sign the owner message. Must match SessionRegistry.registerSession exactly:
        // sha256(abi.encode(SESSION_REGISTER_MSG, chainId, address(this), expireAt, sessionId,
        //                   workloadId, baseImageId, platformProfileId, variantId, sessionKeyFingerprint))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
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
                expire_at,
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
    pub async fn rotate_session(
        &self,
        signer: &PrivateKeySigner,
        old_session_id: B256,
        tee_report_bytes_hash: B256,
        rotation_evidence: SessionRotationEvidence,
        expire_offset_secs: u64,
    ) -> Result<RotateSessionResponse> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let expire_at = expire_at(expire_offset_secs);

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();

        // Pre-compute newSessionId
        let new_session_id = compute_new_session_id(
            tee_report_bytes_hash,
            &rotation_evidence.tpm_quote_report.data,
        )?;

        info!(
            address = %self.stub.address(),
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            expire_at = expire_at,
            "Submitting rotateSession transaction"
        );

        // Build and sign the message
        // Message: sha256(abi.encode(SESSION_ROTATE_MSG, chainId, contractAddr, expireAt, oldSessionId, newSessionId))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_ROTATE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                old_session_id,
                new_session_id,
            ),
            signer,
        )
        .await?;

        let response = self
            .rotate_session_presigned(
                old_session_id,
                tee_report_bytes_hash,
                rotation_evidence,
                expire_at,
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
        expire_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<RegisterSessionResponse> {
        let session_id =
            compute_session_id_from_parts(&evidence.tpm_quote_report.data, &evidence.tee_report)?;

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            expire_at = expire_at,
            "Submitting registerSession (presigned)"
        );

        // Call the contract
        let pending = self
            .stub
            .registerSession(
                evidence.into(),
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                expire_at,
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
    pub async fn rotate_session_presigned(
        &self,
        old_session_id: B256,
        tee_report_bytes_hash: B256,
        rotation_evidence: SessionRotationEvidence,
        expire_at: u64,
        owner_identity: PublicIdentity,
        owner_signature: Bytes,
    ) -> Result<RotateSessionResponse> {
        // Pre-compute newSessionId
        let new_session_id = compute_new_session_id(
            tee_report_bytes_hash,
            &rotation_evidence.tpm_quote_report.data,
        )?;

        info!(
            address = %self.stub.address(),
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            expire_at = expire_at,
            "Submitting rotateSession (presigned)"
        );

        // Call the contract
        let pending = self
            .stub
            .rotateSession(
                old_session_id,
                tee_report_bytes_hash,
                rotation_evidence.into(),
                expire_at,
                owner_identity.into(),
                owner_signature,
            )
            .send_ex()
            .await?;

        info!(tx_hash = %pending.tx_hash(), "Rotation transaction submitted");

        let mut tx = PendingTxAccum::new(pending, |event, result: &mut RotateSessionResponse| {
            if let SessionRegistryEvents::SessionRotated(msg) = event {
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

    /// Revoke a session in the SessionRegistry contract.
    pub async fn revoke_session(
        &self,
        signer: &PrivateKeySigner,
        session_id: B256,
        expire_offset_secs: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let expire_at = expire_at(expire_offset_secs);

        let chain_id = self.stub.provider().chain_id();

        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_REVOKE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                session_id,
            ),
            signer,
        )
        .await?;

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            expire_at = expire_at,
            "Submitting revokeSession transaction"
        );

        let pending = self
            .stub
            .revokeSession(session_id, expire_at, owner_identity.into(), sig_bytes)
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

/// Compute the `teeReportBytesHash` exactly as `TeeVerifier.getTeeReportHash`
/// (src/TeeVerifier.sol) — the value the contract feeds into the sessionId, which is
/// NOT a plain keccak of the report data for the ZK backends:
///   - `Solidity` (0)            -> `keccak256(data)`
///   - `ZkRiscZero` (1) / `ZkSuccinct` (2) -> decode `data` as `ZkProof` and return the
///     last 32 bytes of `output` (the journal-committed report hash). `SnpZkProof` is
///     ABI-forward-compatible with `ZkProof`, so decoding it as `ZkProof` still reads
///     `output` correctly.
pub fn compute_tee_report_hash(verification_backend_type: u8, data: &Bytes) -> Result<B256> {
    // VerificationBackendType.Solidity == 0 (Evidence.sol).
    if verification_backend_type == 0 {
        return Ok(keccak256(data));
    }
    let zk_proof =
        ZkProof::abi_decode(data).context("Failed to decode ZkProof from teeReport.data")?;
    let output = zk_proof.output;
    if output.len() < 32 {
        anyhow::bail!("ZkProof.output too short: {} < 32", output.len());
    }
    Ok(B256::from_slice(&output[output.len() - 32..]))
}

/// Compute sessionId from the raw TPM quote report data and the TEE report.
///
/// This is useful when you have the raw bytes directly. `tee_report` is taken whole (not
/// just its `data`) because the report hash is backend-dependent — see
/// [`compute_tee_report_hash`].
pub fn compute_session_id_from_parts(
    tpm_quote_report_data: &Bytes,
    tee_report: &TeeReport,
) -> Result<B256> {
    // 1. teeReportBytesHash = TeeVerifier.getTeeReportHash(teeReport)
    let tee_report_bytes_hash =
        compute_tee_report_hash(tee_report.verification_backend_type, &tee_report.data)?;

    // 2. Decode TpmQuoteReport and hash tpmSignature
    let quote_report = TpmQuoteReport::abi_decode(tpm_quote_report_data)
        .context("Failed to decode TpmQuoteReport")?;
    let tpm_signature_hash = keccak256(&quote_report.tpmSignature);

    // 3. Compute sessionId: keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))
    let session_domain = keccak256(b"CVM_SESSION_V1");
    let session_id =
        keccak256((session_domain, tpm_signature_hash, tee_report_bytes_hash).abi_encode_params());

    Ok(session_id)
}

/// Compute new sessionId for rotation from teeReportBytesHash and new TPM quote report.
///
/// This matches the contract's computation:
/// ```solidity
/// TpmQuoteReport memory quoteReport = abi.decode(rotationEvidence.tpmQuoteReport.data, (TpmQuoteReport));
/// bytes32 newTpmSignatureHash = keccak256(quoteReport.tpmSignature);
/// newSessionId = keccak256(abi.encode(SESSION_DOMAIN, newTpmSignatureHash, teeReportBytesHash));
/// ```
pub fn compute_new_session_id(
    tee_report_bytes_hash: B256,
    tpm_quote_report_data: &Bytes,
) -> Result<B256> {
    // Decode TpmQuoteReport and hash tpmSignature
    let quote_report = TpmQuoteReport::abi_decode(tpm_quote_report_data)
        .context("Failed to decode TpmQuoteReport for rotation")?;
    let new_tpm_signature_hash = keccak256(&quote_report.tpmSignature);

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
    use super::compute_tee_report_hash;
    use alloy::primitives::{Bytes, keccak256};
    use alloy::sol;
    use alloy::sol_types::SolValue;

    sol! {
        // Same layout as Evidence.sol SnpZkProof (the 3-field SNP container). teeReport.data
        // for SEV-SNP is `abi.encode(SnpZkProof{output, proofBytes, rawReport})`.
        struct SnpZkProof {
            bytes output;
            bytes proofBytes;
            bytes rawReport;
        }
    }

    /// For the ZK backends, `teeReportBytesHash` is the journal's trailing 32 bytes
    /// (== keccak256(rawReport) for SNP), NOT `keccak256(teeReport.data)`. This is the
    /// exact behaviour of `TeeVerifier.getTeeReportHash`, and a regression guard against
    /// the stale `keccak256(data)` the SDK used to compute — which silently produced a
    /// wrong sessionId for every ZK (SNP) registration.
    #[test]
    fn tee_report_hash_zk_uses_journal_tail_not_keccak_of_data() {
        let raw_report = Bytes::from(vec![0xABu8; 1184]); // SNP report is 1184 bytes
        let report_hash = keccak256(&raw_report); // journal binds keccak256(report)

        // Journal output: arbitrary prefix, then the trailing 32-byte report hash.
        let mut output = vec![0x11u8; 96];
        output.extend_from_slice(report_hash.as_slice());

        // teeReport.data = abi.encode(SnpZkProof{...}) — 3 fields; decoded on-chain as the
        // 2-field ZkProof (ABI-forward-compatible), so `output` is still read correctly.
        let data: Bytes = SnpZkProof {
            output: output.into(),
            proofBytes: Bytes::from(vec![0x22u8; 260]),
            rawReport: raw_report.clone(),
        }
        .abi_encode()
        .into();

        // ZkRiscZero (1) and ZkSuccinct (2) both take the journal tail.
        for backend in [1u8, 2u8] {
            let h = compute_tee_report_hash(backend, &data).unwrap();
            assert_eq!(
                h, report_hash,
                "ZK backend {backend} must return the journal tail"
            );
            assert_ne!(
                h,
                keccak256(&data),
                "ZK hash must NOT be keccak256(teeReport.data)"
            );
        }

        // Solidity (0) keeps keccak256(data).
        assert_eq!(compute_tee_report_hash(0, &data).unwrap(), keccak256(&data));
    }

    #[test]
    fn tee_report_hash_zk_rejects_short_output() {
        let data: Bytes = SnpZkProof {
            output: Bytes::from(vec![0u8; 8]), // < 32 bytes
            proofBytes: Bytes::new(),
            rawReport: Bytes::new(),
        }
        .abi_encode()
        .into();
        assert!(compute_tee_report_hash(2, &data).is_err());
    }
}
