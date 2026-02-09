//! WorkloadRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use tracing::info;

use crate::stubs::WorkloadRegistry::{
    WorkloadRegistryEvents, WorkloadRegistryInstance, WorkloadSpec,
};
use crate::stubs::{PublicIdentity, sign_message};
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
        expire_offset_secs: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        // Calculate expiration timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expire_at = current_timestamp + expire_offset_secs;

        let workload_id = Self::get_workload_id(&AppRef::new(&spec.name, &spec.version));

        info!(
            address = %self.stub.address(),
            expire_at = expire_at,
            workload_name = %spec.name,
            workload_version = %spec.version,
            workload_id = %workload_id,
            "Submitting registerWorkload transaction"
        );

        // Get chain ID
        let chain_id = self
            .stub
            .provider()
            .get_chain_id()
            .await
            .context("Failed to get chain ID")?;

        // Build and sign the message
        // Message: sha256(abi.encode(WORKLOAD_REGISTER_MSG, chainId, contractAddr, expireAt, spec))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_WORKLOAD_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                spec.clone(),
            ),
            signer,
        )
        .await?;

        // Call the contract
        let pending = self
            .stub
            .registerWorkload(spec, expire_at, owner_identity.into(), sig_bytes)
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
}
