//! WorkloadRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum, ProviderEx};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::stubs::WorkloadRegistry::{
    WorkloadRegistryEvents, WorkloadRegistryInstance, WorkloadSpec,
};
use crate::stubs::{PublicIdentity, op_expires_at, sign_message};
use crate::types::AppRef;

pub struct WorkloadRegistry {
    stub: WorkloadRegistryInstance<NetworkProvider>,
}

impl WorkloadRegistry {
    pub fn new(contract: Address, p: NetworkProvider) -> Self {
        Self {
            stub: WorkloadRegistryInstance::new(contract, p),
        }
    }

    pub fn get_workload_id(app_ref: &AppRef) -> B256 {
        app_ref.id("CVM_WORKLOAD_V1")
    }

    pub async fn get_workload_spec(&self, workload_id: B256) -> Result<WorkloadSpec> {
        let spec = self.stub.getWorkload(workload_id).call_ex().await?;
        Ok(spec)
    }

    /// Register a workload to the WorkloadRegistry contract.
    ///
    /// This function:
    /// 1. Builds the signature message matching the contract's expected format
    /// 2. Signs the message with the provided private key
    /// 3. Submits the transaction and waits for confirmation
    /// 4. Returns the workloadId from the emitted event
    pub async fn register_workload(
        &self,
        signer: &PrivateKeySigner,
        spec: WorkloadSpec,
        op_expiry_seconds: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let op_expires_at = op_expires_at(op_expiry_seconds);

        let workload_id = Self::get_workload_id(&AppRef::new(
            owner_identity.fingerprint(),
            &spec.name,
            &spec.version,
        ));

        info!(
            address = %self.stub.address(),
            op_expires_at = op_expires_at,
            workload_name = %spec.name,
            workload_version = %spec.version,
            workload_id = %workload_id,
            "Submitting registerWorkload transaction"
        );

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();

        // Build and sign the message
        // Message: sha256(abi.encode(WORKLOAD_REGISTER_MSG, chainId, contractAddr, opExpiresAt, spec))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_WORKLOAD_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(op_expires_at),
                spec.clone(),
            ),
            signer,
        )
        .await?;

        debug!("spec: {:?}", spec);
        debug!("op_expires_at: {}", op_expires_at);
        debug!("owner_identity: {:?}", owner_identity);
        debug!("sig_bytes: {:?}", sig_bytes);

        // Call the contract
        let pending = self
            .stub
            .registerWorkload(spec, op_expires_at, owner_identity.into(), sig_bytes)
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();

        info!(tx_hash = %tx_hash, "Transaction submitted");

        let mut tx = PendingTxAccum::new(pending, |event, result: &mut B256| {
            if let WorkloadRegistryEvents::WorkloadRegistered(msg) = event {
                *result = msg.workloadId
            }
        });

        let workload_id = tx
            .result()
            .await
            .context("Failed to get transaction receipt")?;

        Ok(workload_id)
    }

    /// Deactivate a workload in the WorkloadRegistry contract.
    pub async fn deactivate_workload(
        &self,
        signer: &PrivateKeySigner,
        workload_id: B256,
        op_expiry_seconds: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let op_expires_at = op_expires_at(op_expiry_seconds);

        let chain_id = self.stub.provider().chain_id();

        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_WORKLOAD_DEACTIVATE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(op_expires_at),
                workload_id,
            ),
            signer,
        )
        .await?;

        info!(
            address = %self.stub.address(),
            workload_id = %workload_id,
            op_expires_at = op_expires_at,
            "Submitting deactivateWorkload transaction"
        );

        let pending = self
            .stub
            .deactivateWorkload(workload_id, op_expires_at, owner_identity.into(), sig_bytes)
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();
        info!(tx_hash = %tx_hash, "Deactivation transaction submitted");

        let mut tx = PendingTxAccum::new(pending, move |event, found: &mut bool| {
            if let WorkloadRegistryEvents::WorkloadDeactivated(msg) = event {
                if msg.workloadId == workload_id {
                    *found = true;
                }
            }
        });

        let found = tx
            .result()
            .await
            .context("Failed to get deactivation receipt")?;

        anyhow::ensure!(
            found,
            "No WorkloadDeactivated event with expected workloadId {workload_id}"
        );

        Ok(tx.tx_hash())
    }

    /// Get the owner fingerprint of a workload.
    pub async fn get_workload_owner(&self, workload_id: B256) -> Result<B256> {
        let owner = self.stub.getWorkloadOwner(workload_id).call_ex().await?;
        Ok(owner)
    }

    /// Check if a workload has been revoked.
    pub async fn is_workload_revoked(&self, workload_id: B256) -> Result<bool> {
        let revoked = self.stub.isWorkloadRevoked(workload_id).call_ex().await?;
        Ok(revoked)
    }

    /// Check if a base image is allowed for a given workload.
    pub async fn is_base_image_allowed(
        &self,
        workload_id: B256,
        base_image_id: B256,
    ) -> Result<bool> {
        let allowed = self
            .stub
            .isBaseImageAllowed(workload_id, base_image_id)
            .call_ex()
            .await?;
        Ok(allowed)
    }

    /// Add fingerprints to the whitelist (onlyOwner).
    pub async fn add_to_whitelist(&self, fingerprints: Vec<B256>) -> Result<B256> {
        let mut pending = self.stub.addToWhitelist(fingerprints).send_ex().await?;
        let tx_hash = pending.tx_hash();
        pending
            .get_receipt()
            .await
            .context("Failed to get whitelist add receipt")?;
        Ok(tx_hash)
    }

    /// Remove a fingerprint from the whitelist (onlyOwner).
    pub async fn remove_from_whitelist(&self, fingerprint: B256) -> Result<B256> {
        let mut pending = self.stub.removeFromWhitelist(fingerprint).send_ex().await?;
        let tx_hash = pending.tx_hash();
        pending
            .get_receipt()
            .await
            .context("Failed to get whitelist remove receipt")?;
        Ok(tx_hash)
    }

    /// Check if a fingerprint is whitelisted.
    pub async fn is_whitelisted(&self, fingerprint: B256) -> Result<bool> {
        let whitelisted = self.stub.isWhitelisted(fingerprint).call_ex().await?;
        Ok(whitelisted)
    }
}
