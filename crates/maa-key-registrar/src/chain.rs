//! Alloy bindings for `MaaKeyRegistry` + a thin client wrapping the
//! four registry functions.
//!
//! Inline `alloy::sol!` rather than wiring the contract artifact through
//! `contract_artifacts/sync.sh` — the surface is small, so duplicating the
//! signatures and revert reasons costs less than adding a build-order
//! dependency on `forge build`. Keep this `sol!` block in sync with
//! `src/MaaKeyRegistry.sol` if the contract's functions or errors change.

use std::time::Duration;

use alloy::ext::{CallBuilderEx, NetworkProvider};
use alloy::primitives::{Address, B256, Bytes};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};

alloy::sol! {
    #[sol(rpc, all_derives)]
    interface IMaaKeyRegistry {
        struct MaaSigningKey {
            bytes pkcs1Pubkey;
            bytes32 issuerHash;
            uint64 notAfter;
            bool revoked;
        }

        function upsertMaaSigningKey(
            bytes32 kidHash,
            bytes calldata pkcs1Pubkey,
            bytes32 issuerHash,
            uint64 notAfter
        ) external;

        function revokeMaaSigningKey(bytes32 kidHash) external;

        function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory);

        function hasMaaSigningKey(bytes32 kidHash) external view returns (bool);

        // Revert reasons the registrar can hit. Mirrors src/MaaKeyRegistry.sol
        // (custom errors) plus OwnableUpgradeable's owner gate. Kept in sync so
        // send_ex/call_ex can decode reverts into a readable cause.
        error EmptyPubkey();
        error EmptyIssuerHash();
        error NotAfterInPast(uint64 notAfter, uint64 nowTs);
        error KidNotRegistered(bytes32 kidHash);
        error KidRevoked(bytes32 kidHash);
        error OwnableUnauthorizedAccount(address account);
    }
}

alloy::register_contract_errors!(IMaaKeyRegistry);

use IMaaKeyRegistry::IMaaKeyRegistryInstance;
pub use IMaaKeyRegistry::MaaSigningKey;

/// Thin client wrapping the four `MaaKeyRegistry` calls.
pub struct MaaKeyRegistryClient {
    stub: IMaaKeyRegistryInstance<NetworkProvider>,
}

impl MaaKeyRegistryClient {
    /// Build a read-only client (no signer). Suitable for `derive` / `status`
    /// subcommands that only need view calls.
    pub async fn read_only(rpc_url: &str, registry: Address) -> Result<Self> {
        let provider = build_provider(rpc_url).await?;
        Ok(Self {
            stub: IMaaKeyRegistryInstance::new(registry, provider),
        })
    }

    /// Build a write-capable client that signs txs with `owner_key`.
    /// The owner key is the contract's `OwnableUpgradeable` owner; the caller
    /// is responsible for confirming this off-band.
    pub async fn with_signer(
        rpc_url: &str,
        registry: Address,
        owner_key: PrivateKeySigner,
    ) -> Result<Self> {
        let provider = build_provider(rpc_url).await?.with_signer(owner_key);
        Ok(Self {
            stub: IMaaKeyRegistryInstance::new(registry, provider),
        })
    }

    pub async fn get_key(&self, kid_hash: B256) -> Result<MaaSigningKey> {
        Ok(self.stub.getMaaSigningKey(kid_hash).call_ex().await?)
    }

    /// Submit `upsertMaaSigningKey` and wait for the receipt. Returns the
    /// tx hash on success.
    pub async fn upsert(
        &self,
        kid_hash: B256,
        pkcs1_pubkey: Bytes,
        issuer_hash: B256,
        not_after: u64,
    ) -> Result<B256> {
        let call = self
            .stub
            .upsertMaaSigningKey(kid_hash, pkcs1_pubkey, issuer_hash, not_after);
        let mut pending = call
            .send_ex()
            .await
            .context("submitting upsertMaaSigningKey")?;
        let tx_hash = pending.tx_hash();
        let _receipt = pending.get_receipt().await.context("awaiting receipt")?;
        Ok(tx_hash)
    }

    /// Submit `revokeMaaSigningKey` and wait for the receipt.
    pub async fn revoke(&self, kid_hash: B256) -> Result<B256> {
        let call = self.stub.revokeMaaSigningKey(kid_hash);
        let mut pending = call
            .send_ex()
            .await
            .context("submitting revokeMaaSigningKey")?;
        let tx_hash = pending.tx_hash();
        let _receipt = pending.get_receipt().await.context("awaiting receipt")?;
        Ok(tx_hash)
    }
}

async fn build_provider(rpc_url: &str) -> Result<NetworkProvider> {
    NetworkProvider::with_http(
        rpc_url,
        Some(Duration::from_secs(2)),
        Some(Duration::from_secs(60)),
        100,
    )
    .await
    .with_context(|| format!("connecting to {rpc_url}"))
}
