//! Relay service for session registry operations.
//!
//! Provides a JSON-based interface for submitting pre-signed session operations.
//! The relay uses its own private key for gas payment but relies on externally
//! signed owner signatures for authorization.

use std::time::Duration;

use alloy::ext::NetworkProvider;
use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tracing::info;

use crate::session_registry::{
    SessionRegistry, compute_new_session_id, compute_session_id_from_parts,
};
use crate::stubs::PublicIdentity;

use crate::types::{
    RegisterSessionRequest, RegisterSessionResponse, RotateSessionRequest, RotateSessionResponse,
};

// ============================================================================
// Request/Response Types
// ============================================================================

// ============================================================================
// Type Conversions
// ============================================================================

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
        // Decode IDs
        let workload_id = request.workload_id;
        let base_image_id = request.base_image_id;
        let platform_profile_id = request.platform_profile_id;
        let variant_id = request.variant_id;

        // Convert owner identity
        let owner_identity = PublicIdentity {
            typeId: request.owner_identity.typeId,
            key: request.owner_identity.key,
        };

        // Decode owner signature
        let owner_signature: Bytes = request.owner_signature;

        // Pre-compute session ID for logging
        let session_id = compute_session_id_from_parts(
            &request.evidence.tpmQuoteReport.data,
            &request.evidence.teeReport.data,
        )?;

        info!(
            session_id = %session_id,
            workload_id = %workload_id,
            base_image_id = %base_image_id,
            "Relay: submitting registerSession"
        );

        // Submit transaction
        let response = self
            .registry
            .register_session_presigned(
                request.evidence,
                workload_id,
                base_image_id,
                platform_profile_id,
                variant_id,
                request.expire_at,
                owner_identity,
                owner_signature,
            )
            .await?;

        Ok(response)
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
        let rotation_evidence = request.rotation_evidence;

        // Convert owner identity
        let owner_identity = PublicIdentity {
            typeId: request.owner_identity.typeId,
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
        let response = self
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

        Ok(response)
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
