//! SessionRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum, ProviderEx};
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use tracing::info;

use crate::base_image_registry::BaseImageRegistry;
use crate::stubs::SessionRegistry::{SessionRegistryEvents, SessionRegistryInstance};
use crate::stubs::{
    AttestationEvidence, PublicIdentity, SessionRotationEvidence, TpmQuoteReport, sign_message,
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

        // Calculate expiration timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expire_at = current_timestamp + expire_offset_secs;

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();
        let session_id = compute_session_id_from_parts(
            &evidence.tpm_quote_report.data,
            &evidence.tee_report.data,
        )?;
        let workload_id = WorkloadRegistry::get_workload_id(&workload_ref);
        let base_image_id = BaseImageRegistry::get_image_id(&base_image_ref);

        info!(
            address = %self.stub.address(),
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            expire_at = expire_at,
            "Submitting registerSession transaction"
        );

        // Build and sign the message
        // Message: sha256(abi.encode(SESSION_REGISTER_MSG, chainId, contractAddr, expireAt, sessionId))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_SESSION_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                session_id,
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

        // Calculate expiration timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expire_at = current_timestamp + expire_offset_secs;

        // Get chain ID
        let chain_id = self
            .stub
            .provider()
            .get_chain_id()
            .await
            .context("Failed to get chain ID")?;

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
        let session_id = compute_session_id_from_parts(
            &evidence.tpm_quote_report.data,
            &evidence.tee_report.data,
        )?;

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

        let tx_hash = B256::from(*pending.tx_hash());
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
}

/// Compute sessionId from raw TPM quote report data and TEE report data.
///
/// This is useful when you have the raw bytes directly.
pub fn compute_session_id_from_parts(
    tpm_quote_report_data: &Bytes,
    tee_report_data: &Bytes,
) -> Result<B256> {
    // 1. Hash teeReport.data
    let tee_report_bytes_hash = keccak256(tee_report_data);

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
