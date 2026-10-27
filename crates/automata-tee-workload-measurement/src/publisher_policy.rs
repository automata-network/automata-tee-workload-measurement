//! Publisher-approved policy digests. These match PublisherPolicy.sol exactly.
//! They contain no publication deadline, chain ID, or registry address.
use crate::stubs::WorkloadRegistry::WorkloadSpec;
use crate::stubs::{MeasurementVariant, PlatformProfile, sign_message};
use alloy::{
    primitives::{B256, Bytes, keccak256},
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

pub fn variant_digest(id: B256, profile: &PlatformProfile, variant: &MeasurementVariant) -> B256 {
    B256::from_slice(&Sha256::digest(
        (
            keccak256("CVM_BASEIMAGE_VARIANT_SIGNATURE_V1"),
            id,
            profile.clone(),
            variant.clone(),
        )
            .abi_encode_params(),
    ))
}

pub fn workload_digest(id: B256, spec: &WorkloadSpec) -> B256 {
    B256::from_slice(&Sha256::digest(
        (
            keccak256("CVM_WORKLOAD_POLICY_SIGNATURE_V1"),
            id,
            spec.clone(),
        )
            .abi_encode_params(),
    ))
}

pub async fn sign_variants(
    signer: &PrivateKeySigner,
    id: B256,
    profiles: &[PlatformProfile],
    variants: &[Vec<MeasurementVariant>],
) -> Result<Vec<Vec<Bytes>>> {
    ensure!(
        profiles.len() == variants.len(),
        "one variant row is required for each platform profile"
    );
    let mut signatures = Vec::with_capacity(profiles.len());
    for (profile, row) in profiles.iter().zip(variants) {
        let mut signed_row = Vec::with_capacity(row.len());
        for variant in row {
            signed_row.push(
                sign_message(
                    &(
                        keccak256("CVM_BASEIMAGE_VARIANT_SIGNATURE_V1"),
                        id,
                        profile.clone(),
                        variant.clone(),
                    ),
                    signer,
                )
                .await?,
            );
        }
        signatures.push(signed_row);
    }
    Ok(signatures)
}

pub async fn sign_workload(
    signer: &PrivateKeySigner,
    id: B256,
    spec: &WorkloadSpec,
) -> Result<Bytes> {
    sign_message(
        &(
            keccak256("CVM_WORKLOAD_POLICY_SIGNATURE_V1"),
            id,
            spec.clone(),
        ),
        signer,
    )
    .await
}
