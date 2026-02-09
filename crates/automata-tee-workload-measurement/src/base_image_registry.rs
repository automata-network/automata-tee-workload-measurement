//! BaseImageRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use tracing::info;

use crate::stubs::BaseImageRegistry::{
    BaseImageRegistryEvents, BaseImageRegistryInstance, BaseImageSpec, MeasurementVariant,
    PlatformProfile,
};
use crate::stubs::{PublicIdentity, sign_message};

pub struct BaseImageRegistry {
    stub: BaseImageRegistryInstance<NetworkProvider>,
}

#[derive(Debug, Default, Clone)]
pub struct BaseImageResult {
    pub base_image_id: B256,
    pub platform_profile_ids: Vec<B256>,
    pub variant_id: Vec<Vec<B256>>,
}

impl BaseImageRegistry {
    pub fn new(contract: Address, p: NetworkProvider) -> Self {
        Self {
            stub: BaseImageRegistryInstance::new(contract, p),
        }
    }

    pub fn get_image_id(name: &str, version: &str) -> B256 {
        keccak256((keccak256("CVM_BASEIMAGE_V1"), name, version).abi_encode_params())
    }

    pub fn get_platform_profile_id(image_id: B256, profile_name: &str) -> B256 {
        keccak256(
            (keccak256("CVM_PLATFORM_PROFILE_V1"), image_id, profile_name).abi_encode_params(),
        )
    }

    pub fn get_variant_id(profile_id: B256, variant_name: &str) -> B256 {
        keccak256(
            (
                keccak256("CVM_PLATFORM_VARIANT_V1"),
                profile_id,
                variant_name,
            )
                .abi_encode_params(),
        )
    }

    /// Register a base image to the BaseImageRegistry contract.
    ///
    /// This function:
    /// 1. Builds the signature message matching the contract's expected format
    /// 2. Signs the message with the provided private key
    /// 3. Submits the transaction and waits for confirmation
    pub async fn register_base_image(
        &self,
        signer: &PrivateKeySigner,
        spec: BaseImageSpec,
        platform_profiles: Vec<PlatformProfile>,
        measurement_variants: Vec<Vec<MeasurementVariant>>,
        expire_offset_secs: u64,
    ) -> Result<BaseImageResult> {
        let image_id = Self::get_image_id(&spec.name, &spec.version);
        for item in &platform_profiles {
            let profile_id = Self::get_platform_profile_id(image_id, &item.name);
            for variant in measurement_variants.iter().flatten() {
                let variant_id = Self::get_variant_id(profile_id, &variant.name);
                info!(
                    image_id = %image_id,
                    profile_id = %profile_id,
                    profile_name = %item.name,
                    variant_id = %variant_id,
                    variant_name = %variant.name,
                    "Computed IDs for base image registration"
                );
            }
        }
        let owner_identity = PublicIdentity::secp256k1(signer);

        // Calculate expiration timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expire_at = current_timestamp + expire_offset_secs;

        info!(
            address = %self.stub.address(),
            expire_at = expire_at,
            "Submitting registerBaseImage transaction"
        );

        // Get chain ID
        let chain_id = self
            .stub
            .provider()
            .get_chain_id()
            .await
            .context("Failed to get chain ID")?;

        // Build and sign the message
        // Message: sha256(abi.encode(domain, chainId, contractAddr, expireAt, spec, profiles, variants))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_BASEIMAGE_REGISTER_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                spec.clone(),
                platform_profiles.clone(),
                measurement_variants.clone(),
            ),
            &signer,
        )
        .await?;

        // Call the contract
        let pending = self
            .stub
            .registerBaseImage(
                spec,
                platform_profiles,
                measurement_variants,
                expire_at,
                owner_identity.into(),
                sig_bytes,
            )
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();

        info!(tx_hash = %tx_hash, "Transaction submitted");

        let mut tx =
            PendingTxAccum::new(pending, |event, result: &mut BaseImageResult| match event {
                BaseImageRegistryEvents::BaseImageRegistered(msg) => {
                    result.base_image_id = msg.baseImageId;
                }
                BaseImageRegistryEvents::PlatformProfileRegistered(msg) => {
                    result.platform_profile_ids.push(msg.platformProfileId);
                    result.variant_id.push(vec![]);
                }
                BaseImageRegistryEvents::MeasurementVariantRegistered(msg) => {
                    if let Some(idx) = result
                        .platform_profile_ids
                        .iter()
                        .position(|id| id == &msg.platformProfileId)
                    {
                        result.variant_id[idx].push(msg.variantId);
                    }
                }
                _ => {}
            });

        Ok(tx
            .result()
            .await
            .context("Failed to get transaction receipt")?)
    }
}
