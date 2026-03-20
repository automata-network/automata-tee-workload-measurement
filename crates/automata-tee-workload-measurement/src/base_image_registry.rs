//! BaseImageRegistry contract interaction.

use alloy::ext::{CallBuilderEx, NetworkProvider, PendingTxAccum, ProviderEx};
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::stubs::BaseImageRegistry::{BaseImageRegistryEvents, BaseImageRegistryInstance};
use crate::stubs::{
    BaseImageSpec, MeasurementVariant, PlatformProfile, PublicIdentity, expire_at, sign_message,
};
use crate::types::AppRef;

#[derive(Debug, Clone)]
pub struct BaseImageRegistry {
    stub: BaseImageRegistryInstance<NetworkProvider>,
}

#[derive(Debug, Default, Clone)]
pub struct BaseImageResult {
    pub base_image_id: B256,
    pub platform_profile_ids: Vec<B256>,
    pub variant_id: Vec<Vec<B256>>,
}

#[derive(Debug, Default, Clone)]
pub struct BaseImageInfo {
    pub spec: BaseImageSpec,
    pub profile: PlatformProfile,
    pub variant: Option<MeasurementVariant>,
}

/// Full hierarchy of a base image: all profiles and their variants.
#[derive(Debug, Clone)]
pub struct BaseImageHierarchy {
    pub base_image_id: B256,
    pub spec: BaseImageSpec,
    pub profiles: Vec<ProfileWithVariants>,
}

/// A platform profile together with its measurement variants.
#[derive(Debug, Clone)]
pub struct ProfileWithVariants {
    pub profile_id: B256,
    pub profile: PlatformProfile,
    pub variants: Vec<(B256, MeasurementVariant)>,
}

impl BaseImageRegistry {
    pub fn new(contract: Address, p: NetworkProvider) -> Self {
        Self {
            stub: BaseImageRegistryInstance::new(contract, p),
        }
    }

    pub fn get_image_id(app_ref: &AppRef) -> B256 {
        app_ref.id("CVM_BASEIMAGE_V1")
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

    /// Get the complete hierarchy for a base image: spec + all profiles + all variants.
    ///
    /// Since `platformProfileIds` and `variantIds` are private arrays in the contract,
    /// we read them via `eth_getStorageAt` by computing their storage slots directly.
    ///
    /// Storage layout (OZ upgradeable contracts use namespaced storage, so our
    /// mappings start at slot 0):
    ///
    /// ```text
    /// slot 0: mapping(bytes32 => BaseImageSpecStorage) _baseImages
    ///   base = keccak256(key ++ slot)
    ///   base+5: platformProfileIds.length
    ///   keccak256(base+5)+i: platformProfileIds[i]
    ///
    /// slot 1: mapping(bytes32 => PlatformProfileStorage) _platformProfiles
    ///   base = keccak256(key ++ slot)
    ///   base+4: variantIds.length
    ///   keccak256(base+4)+i: variantIds[i]
    /// ```
    pub async fn get_hierarchy(&self, base_image_id: B256) -> Result<BaseImageHierarchy> {
        let provider = self.stub.provider();
        let addr = *self.stub.address();

        // 1. Fetch spec via public getter
        let spec = self.stub.getBaseImage(base_image_id).call().await?;

        // 2. Read platformProfileIds from storage
        let profile_ids = read_bytes32_array(
            provider,
            addr,
            mapping_struct_slot(base_image_id, U256::from(0)),
            5, // platformProfileIds offset in BaseImageSpecStorage
        )
        .await?;

        // 3. For each profile, read variantIds and fetch data
        let mut profiles = Vec::with_capacity(profile_ids.len());
        for profile_id in &profile_ids {
            let profile = self.stub.getPlatformProfile(*profile_id).call().await?;

            let variant_ids = read_bytes32_array(
                provider,
                addr,
                mapping_struct_slot(*profile_id, U256::from(1)),
                4, // variantIds offset in PlatformProfileStorage
            )
            .await?;

            let mut variants = Vec::with_capacity(variant_ids.len());
            for variant_id in &variant_ids {
                let variant = self.stub.getMeasurementVariant(*variant_id).call().await?;
                variants.push((*variant_id, variant));
            }

            profiles.push(ProfileWithVariants {
                profile_id: *profile_id,
                profile,
                variants,
            });
        }

        Ok(BaseImageHierarchy {
            base_image_id,
            spec,
            profiles,
        })
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
        let image_id = Self::get_image_id(&AppRef::new(&spec.name, &spec.version));
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

        let expire_at = expire_at(expire_offset_secs);

        info!(
            address = %self.stub.address(),
            expire_at = expire_at,
            "Submitting registerBaseImage transaction"
        );

        // Get chain ID
        let chain_id = self.stub.provider().chain_id();

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

        debug!("spec: {:?}", spec);
        debug!("platform_profiles: {:?}", platform_profiles);
        debug!("measurement_variants: {:?}", measurement_variants);
        debug!("expire_at: {}", expire_at);
        debug!("owner_identity: {:?}", owner_identity);
        debug!("sig_bytes: {:?}", sig_bytes);

        // Call the contract
        let call = self.stub.registerBaseImage(
            spec,
            platform_profiles,
            measurement_variants,
            expire_at,
            owner_identity.into(),
            sig_bytes,
        );

        let pending = call.send_ex().await?;

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

    /// Deactivate a base image in the BaseImageRegistry contract.
    pub async fn deactivate_base_image(
        &self,
        signer: &PrivateKeySigner,
        base_image_id: B256,
        expire_offset_secs: u64,
    ) -> Result<B256> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let expire_at = expire_at(expire_offset_secs);

        let chain_id = self.stub.provider().chain_id();

        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_BASEIMAGE_DEACTIVATE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                base_image_id,
            ),
            signer,
        )
        .await?;

        info!(
            address = %self.stub.address(),
            base_image_id = %base_image_id,
            expire_at = expire_at,
            "Submitting deactivateBaseImage transaction"
        );

        let pending = self
            .stub
            .deactivateBaseImage(base_image_id, expire_at, owner_identity.into(), sig_bytes)
            .send_ex()
            .await?;

        let tx_hash = pending.tx_hash();
        info!(tx_hash = %tx_hash, "Deactivation transaction submitted");

        let mut tx = PendingTxAccum::new(pending, move |event, found: &mut bool| {
            if let BaseImageRegistryEvents::BaseImageDeactivated(msg) = event {
                if msg.baseImageId == base_image_id {
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
            "No BaseImageDeactivated event with expected baseImageId {base_image_id}"
        );

        Ok(tx.tx_hash())
    }

    /// Add platform variants to an existing base image.
    pub async fn add_platform_variants(
        &self,
        signer: &PrivateKeySigner,
        base_image_id: B256,
        platform_profiles: Vec<PlatformProfile>,
        measurement_variants: Vec<Vec<MeasurementVariant>>,
        expire_offset_secs: u64,
    ) -> Result<BaseImageResult> {
        let owner_identity = PublicIdentity::secp256k1(signer);

        let expire_at = expire_at(expire_offset_secs);

        let chain_id = self.stub.provider().chain_id();

        // Message: sha256(abi.encode(BASEIMAGE_UPDATE_MSG, chainId, contractAddr, expireAt, baseImageId, profiles, variants))
        let sig_bytes = sign_message(
            &(
                keccak256(b"CVM_MSG_BASEIMAGE_UPDATE_V1"),
                U256::from(chain_id),
                *self.stub.address(),
                U256::from(expire_at),
                base_image_id,
                platform_profiles.clone(),
                measurement_variants.clone(),
            ),
            signer,
        )
        .await?;

        info!(
            address = %self.stub.address(),
            base_image_id = %base_image_id,
            expire_at = expire_at,
            "Submitting addPlatformVariants transaction"
        );

        let pending = self
            .stub
            .addPlatformVariants(
                base_image_id,
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
                BaseImageRegistryEvents::BaseImageUpdated(msg) => {
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

    /// Get the combined variant info (base image + platform profile + measurement variant).
    pub async fn get_variant(
        &self,
        base_image_id: B256,
        platform_profile_id: B256,
        variant_id: B256,
    ) -> Result<BaseImageInfo> {
        let result = self
            .stub
            .getVariant(base_image_id, platform_profile_id, variant_id)
            .call_ex()
            .await?;
        Ok(BaseImageInfo {
            spec: result.baseImage,
            profile: result.platformProfile,
            variant: Some(result.variant),
        })
    }

    /// Get the owner fingerprint of a base image.
    pub async fn get_base_image_owner(&self, base_image_id: B256) -> Result<B256> {
        let owner = self.stub.getBaseImageOwner(base_image_id).call_ex().await?;
        Ok(owner)
    }

    /// Check if a base image has been revoked.
    pub async fn is_base_image_revoked(&self, base_image_id: B256) -> Result<bool> {
        let revoked = self
            .stub
            .isBaseImageRevoked(base_image_id)
            .call_ex()
            .await?;
        Ok(revoked)
    }

    /// Check if a measurement variant exists.
    pub async fn has_variant(&self, variant_id: B256) -> Result<bool> {
        let exists = self.stub.hasVariant(variant_id).call_ex().await?;
        Ok(exists)
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

// ============================================================================
// Storage layout helpers for reading private arrays via eth_getStorageAt
// ============================================================================

/// Compute the base storage slot for `mapping[key]` where the mapping is at `slot`.
///
/// Solidity storage: `keccak256(abi.encode(key, slot))`
fn mapping_struct_slot(key: B256, slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key.as_slice());
    slot.to_be_bytes::<32>()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| buf[32 + i] = b);
    U256::from_be_bytes(keccak256(buf).0)
}

/// Read a `bytes32[]` dynamic array from contract storage.
///
/// - `struct_base`: base slot of the struct within the mapping
/// - `array_offset`: field offset of the `bytes32[]` within the struct
///
/// The array length is at slot `struct_base + array_offset`.
/// Element `i` is at slot `keccak256(struct_base + array_offset) + i`.
async fn read_bytes32_array(
    provider: &NetworkProvider,
    addr: Address,
    struct_base: U256,
    array_offset: u64,
) -> Result<Vec<B256>> {
    let length_slot = struct_base + U256::from(array_offset);

    // Read array length
    let length_raw = provider
        .get_storage_at(addr, length_slot)
        .await
        .with_context(|| {
            format!(
                "Failed to read array length from storage at slot: {}",
                length_slot
            )
        })?;
    let length = length_raw.to::<u64>();

    if length == 0 {
        return Ok(vec![]);
    }

    // Compute data start slot: keccak256(length_slot)
    let mut slot_bytes = [0u8; 32];
    length_slot
        .to_be_bytes::<32>()
        .iter()
        .enumerate()
        .for_each(|(i, &b)| slot_bytes[i] = b);
    let data_start = U256::from_be_bytes(keccak256(slot_bytes).0);

    // Read each element
    let mut result = Vec::with_capacity(length as usize);
    for i in 0..length {
        let element_slot = data_start + U256::from(i);
        let value = provider
            .get_storage_at(addr, element_slot)
            .await
            .context("Failed to read array element from storage")?;
        result.push(B256::from(value));
    }

    Ok(result)
}
