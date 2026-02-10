use std::time::Duration;

use alloy::{
    ext::{NetworkProvider, ProviderEx},
    primitives::{Address, B256, U256},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    base_image_registry::BaseImageRegistry,
    session_registry::SessionRegistry,
    stubs::PublicIdentity,
    types::{
        RegisterSessionRequest, RegisterSessionResponse, RotateSessionRequest,
        RotateSessionResponse,
    },
    workload_registry::WorkloadRegistry,
};

#[allow(dead_code)]
pub struct WorkloadMeasurement {
    cfg: WorkloadMeasurementConfig,
    provider: NetworkProvider,
    session_registry: SessionRegistry,
    base_image_registry: BaseImageRegistry,
    workload_registry: WorkloadRegistry,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadMeasurementConfig {
    pub rpc_url: String,
    pub relay_key: Option<B256>,
    pub session_registry_address: Address,
}

impl WorkloadMeasurement {
    pub async fn new(cfg: WorkloadMeasurementConfig) -> Result<Self> {
        let polling_time = Some(Duration::from_secs(1));
        let receipt_timeout = Some(Duration::from_secs(37));
        let boost_gas_multiplier = 100;
        let mut provider = NetworkProvider::with_http(
            &cfg.rpc_url,
            polling_time,
            receipt_timeout,
            boost_gas_multiplier,
        )
        .await
        .with_context(|| format!("connect to {}", cfg.rpc_url))?;
        if let Some(relay_key) = &cfg.relay_key {
            let relay_key = PrivateKeySigner::from_bytes(&relay_key)?;
            provider = provider.with_signer(relay_key);
        }
        let session_registry = SessionRegistry::new(cfg.session_registry_address, provider.clone());
        let base_image_registry = session_registry.base_image_registry().await?;
        let workload_registry = session_registry.workload_registry().await?;

        Ok(WorkloadMeasurement {
            cfg,
            provider,
            session_registry,
            base_image_registry,
            workload_registry,
        })
    }

    pub fn base_image_registry(&self) -> &BaseImageRegistry {
        &self.base_image_registry
    }

    pub fn workload_registry(&self) -> &WorkloadRegistry {
        &self.workload_registry
    }

    pub fn session_registry(&self) -> &SessionRegistry {
        &self.session_registry
    }

    pub async fn chain_id(&self) -> u64 {
        self.provider.chain_id()
    }

    pub fn provider(&self) -> &NetworkProvider {
        &self.provider
    }

    pub async fn session_nonce(&self, owner: &PublicIdentity) -> Result<U256> {
        Ok(self.session_registry.get_nonce(owner.fingerprint()).await?)
    }

    pub async fn register_session(
        &self,
        req: RegisterSessionRequest,
    ) -> Result<RegisterSessionResponse> {
        let response = self
            .session_registry
            .register_session_presigned(
                req.evidence.into(),
                req.workload_id,
                req.base_image_id,
                req.platform_profile_id,
                req.variant_id,
                req.expire_at,
                req.owner_identity.into(),
                req.owner_signature,
            )
            .await?;
        Ok(response)
    }

    pub async fn rotate_session(&self, req: RotateSessionRequest) -> Result<RotateSessionResponse> {
        let response = self
            .session_registry
            .rotate_session_presigned(
                req.old_session_id,
                req.tee_report_bytes_hash,
                req.rotation_evidence.into(),
                req.expire_at,
                req.owner_identity.into(),
                req.owner_signature,
            )
            .await?;
        Ok(response)
    }
}
