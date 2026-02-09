//! Relay service for session registry operations.
//!
//! Provides a JSON-based interface for submitting pre-signed session operations.
//! The relay uses its own private key for gas payment but relies on externally
//! signed owner signatures for authorization.

use std::time::Duration;

use alloy::ext::NetworkProvider;
use alloy::primitives::{Address, B256, Bytes};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::session_registry::{SessionRegistry, compute_new_session_id, compute_session_id};
use crate::stubs::SessionRegistry::{
    AkPubCollateral, AttestationEvidence, PublicIdentity as SessionPublicIdentity,
    SessionRotationEvidence, TeeReport, TpmReport,
};

// ============================================================================
// Request/Response Types
// ============================================================================

/// TEE report data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeReportData {
    pub verification_backend_type: u8,
    pub tee_type: u8,
    pub data: Bytes,
}

/// TPM report data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmReportData {
    pub verification_backend_type: u8,
    pub tpm_report_type: u8,
    pub data: Bytes,
}

/// AK pub collateral data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkPubCollateralData {
    pub ak_pub_collateral_type: u8,
    pub data: Bytes,
}

/// Public identity for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentityData {
    pub type_id: u8,
    pub key: Bytes,
}

/// Attestation evidence for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidenceData {
    pub tee_report: TeeReportData,
    pub tpm_quote_report: TpmReportData,
    pub tpm_certify_report: TpmReportData,
    pub ak_pub_collateral: AkPubCollateralData,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentityData,
}

/// Session rotation evidence for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRotationEvidenceData {
    pub tpm_quote_report: TpmReportData,
    pub tpm_certify_report: TpmReportData,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentityData,
    pub rotation_signature: Bytes,
    pub old_tpm_signing_key: PublicIdentityData,
    pub ak_pub: PublicIdentityData,
}

/// Request for registerSession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSessionRequest {
    /// Attestation evidence from CVM agent
    pub evidence: AttestationEvidenceData,
    /// Workload ID (bytes32 hex)
    pub workload_id: B256,
    /// Base image ID (bytes32 hex)
    pub base_image_id: B256,
    /// Platform profile ID (bytes32 hex)
    pub platform_profile_id: B256,
    /// Measurement variant ID (bytes32 hex)
    pub variant_id: B256,
    /// Signature expiration timestamp (unix seconds)
    pub expire_at: u64,
    /// Owner's public identity
    pub owner_identity: PublicIdentityData,
    /// Owner's signature over the registration message (pre-signed)
    pub owner_signature: Bytes,
}

/// Response from registerSession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSessionResponse {
    /// The registered session ID
    pub session_id: B256,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Request for rotateSession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSessionRequest {
    /// Old session ID to rotate from
    pub old_session_id: B256,
    /// Hash of the original TEE report data (keccak256)
    pub tee_report_bytes_hash: B256,
    /// Rotation evidence from CVM agent
    pub rotation_evidence: SessionRotationEvidenceData,
    /// Signature expiration timestamp (unix seconds)
    pub expire_at: u64,
    /// Owner's public identity
    pub owner_identity: PublicIdentityData,
    /// Owner's signature over the rotation message (pre-signed)
    pub owner_signature: Bytes,
}

/// Response from rotateSession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSessionResponse {
    /// The new session ID after rotation
    pub new_session_id: B256,
    /// Transaction hash
    pub tx_hash: B256,
}

// ============================================================================
// Type Conversions
// ============================================================================

impl TryFrom<AttestationEvidenceData> for AttestationEvidence {
    type Error = anyhow::Error;

    fn try_from(data: AttestationEvidenceData) -> Result<Self> {
        Ok(AttestationEvidence {
            teeReport: TeeReport {
                verificationBackendType: data.tee_report.verification_backend_type,
                teeType: data.tee_report.tee_type,
                data: data.tee_report.data,
            },
            tpmQuoteReport: TpmReport {
                verificationBackendType: data.tpm_quote_report.verification_backend_type,
                tpmReportType: data.tpm_quote_report.tpm_report_type,
                data: data.tpm_quote_report.data,
            },
            tpmCertifyReport: TpmReport {
                verificationBackendType: data.tpm_certify_report.verification_backend_type,
                tpmReportType: data.tpm_certify_report.tpm_report_type,
                data: data.tpm_certify_report.data,
            },
            akPubCollateral: AkPubCollateral {
                akPubCollateralType: data.ak_pub_collateral.ak_pub_collateral_type,
                data: data.ak_pub_collateral.data,
            },
            sessionKeySignature: data.session_key_signature,
            sessionKey: SessionPublicIdentity {
                typeId: data.session_key.type_id,
                key: data.session_key.key,
            },
        })
    }
}

impl TryFrom<SessionRotationEvidenceData> for SessionRotationEvidence {
    type Error = anyhow::Error;

    fn try_from(data: SessionRotationEvidenceData) -> Result<Self> {
        Ok(SessionRotationEvidence {
            tpmQuoteReport: TpmReport {
                verificationBackendType: data.tpm_quote_report.verification_backend_type,
                tpmReportType: data.tpm_quote_report.tpm_report_type,
                data: data.tpm_quote_report.data,
            },
            tpmCertifyReport: TpmReport {
                verificationBackendType: data.tpm_certify_report.verification_backend_type,
                tpmReportType: data.tpm_certify_report.tpm_report_type,
                data: data.tpm_certify_report.data,
            },
            sessionKeySignature: data.session_key_signature,
            sessionKey: SessionPublicIdentity {
                typeId: data.session_key.type_id,
                key: data.session_key.key,
            },
            rotationSignature: data.rotation_signature,
            oldTpmSigningKey: SessionPublicIdentity {
                typeId: data.old_tpm_signing_key.type_id,
                key: data.old_tpm_signing_key.key,
            },
            akPub: SessionPublicIdentity {
                typeId: data.ak_pub.type_id,
                key: data.ak_pub.key,
            },
        })
    }
}

// ============================================================================
// Relay Service
// ============================================================================

/// Relay service for submitting session operations.
///
/// The relay uses its own private key for gas payment but relies on
/// externally signed owner signatures for authorization.
pub struct Relay {
    registry: SessionRegistry,
}

impl Relay {
    /// Create a new relay service.
    ///
    /// # Arguments
    /// * `rpc_url` - Ethereum RPC URL
    /// * `session_registry` - SessionRegistry contract address
    /// * `relay_private_key` - Private key for gas payment (hex string with or without 0x)
    pub async fn new(
        rpc_url: &str,
        session_registry: Address,
        relay_private_key: &str,
    ) -> Result<Self> {
        let signer: PrivateKeySigner = relay_private_key
            .parse()
            .context("Failed to parse relay private key")?;

        let provider = NetworkProvider::with_http(
            rpc_url,
            Some(Duration::from_secs(12)),
            Some(Duration::from_secs(36)),
            100,
        )
        .await
        .context("Failed to create network provider")?
        .with_signer(signer);

        let registry = SessionRegistry::new(session_registry, provider);

        Ok(Self { registry })
    }

    /// Register a session from JSON request.
    ///
    /// The caller must provide a pre-signed owner signature.
    pub async fn register_session(
        &self,
        request: RegisterSessionRequest,
    ) -> Result<RegisterSessionResponse> {
        // Convert evidence
        let evidence: AttestationEvidence = request.evidence.try_into()?;

        // Decode IDs
        let workload_id = request.workload_id;
        let base_image_id = request.base_image_id;
        let platform_profile_id = request.platform_profile_id;
        let variant_id = request.variant_id;

        // Convert owner identity
        let owner_identity = SessionPublicIdentity {
            typeId: request.owner_identity.type_id,
            key: request.owner_identity.key,
        };

        // Decode owner signature
        let owner_signature: Bytes = request.owner_signature;

        // Pre-compute session ID for logging
        let session_id = compute_session_id(&evidence)?;

        info!(
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            "Relay: submitting registerSession"
        );

        // Submit transaction
        let (session_id, tx_hash) = self
            .registry
            .register_session_presigned(
                evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                request.expire_at,
                owner_identity,
                owner_signature,
            )
            .await?;

        Ok(RegisterSessionResponse {
            session_id,
            tx_hash,
        })
    }

    /// Rotate a session from JSON request.
    ///
    /// The caller must provide a pre-signed owner signature.
    pub async fn rotate_session(
        &self,
        request: RotateSessionRequest,
    ) -> Result<RotateSessionResponse> {
        // Decode IDs
        let old_session_id = request.old_session_id;
        let tee_report_bytes_hash = request.tee_report_bytes_hash;

        // Convert rotation evidence
        let rotation_evidence: SessionRotationEvidence = request.rotation_evidence.try_into()?;

        // Convert owner identity
        let owner_identity = SessionPublicIdentity {
            typeId: request.owner_identity.type_id,
            key: request.owner_identity.key,
        };

        // Decode owner signature
        let owner_signature: Bytes = request.owner_signature;

        // Pre-compute new session ID for logging
        let new_session_id = compute_new_session_id(
            tee_report_bytes_hash,
            &rotation_evidence.tpmQuoteReport.data,
        )?;

        info!(
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            "Relay: submitting rotateSession"
        );

        // Submit transaction
        let (new_session_id, tx_hash) = self
            .registry
            .rotate_session_presigned(
                old_session_id,
                tee_report_bytes_hash,
                rotation_evidence,
                request.expire_at,
                owner_identity,
                owner_signature,
            )
            .await?;

        Ok(RotateSessionResponse {
            new_session_id,
            tx_hash,
        })
    }

    /// Register a session from JSON string.
    pub async fn register_session_json(&self, json: &str) -> Result<String> {
        let request: RegisterSessionRequest =
            serde_json::from_str(json).context("Failed to parse RegisterSessionRequest")?;
        let response = self.register_session(request).await?;
        serde_json::to_string(&response).context("Failed to serialize RegisterSessionResponse")
    }

    /// Rotate a session from JSON string.
    pub async fn rotate_session_json(&self, json: &str) -> Result<String> {
        let request: RotateSessionRequest =
            serde_json::from_str(json).context("Failed to parse RotateSessionRequest")?;
        let response = self.rotate_session(request).await?;
        serde_json::to_string(&response).context("Failed to serialize RotateSessionResponse")
    }
}
