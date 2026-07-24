use alloy::{
    primitives::{B256, Bytes, keccak256},
    sol_types::SolValue,
};
use anyhow::ensure;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::sync::LazyLock;

use crate::stubs::{
    AttestationEvidence, PublicIdentity, SessionKeyRotationEvidence, SessionRenewalAuthorization,
};

pub const TEE_ATTRIBUTE_NAMESPACE: &str = "atakit.attestation.v1.tee.";
pub const TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME: &str =
    "atakit.attestation.v1.tee.intel-tdx.debug.enabled";
pub const TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.debug.enabled";
pub const TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled";

pub static TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME));

pub fn tee_attribute_key(name: &str) -> Option<B256> {
    match name {
        TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME => Some(*TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY),
        TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME => Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY),
        TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME => {
            Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY)
        }
        _ => None,
    }
}

pub fn tee_attribute_name(key: B256) -> Option<&'static str> {
    if key == *TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY {
        Some(TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME)
    } else if key == *TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY {
        Some(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME)
    } else if key == *TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY {
        Some(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME)
    } else {
        None
    }
}

pub fn tee_attribute_boolean_value(value: bool) -> B256 {
    if value {
        B256::with_last_byte(1)
    } else {
        B256::ZERO
    }
}

pub fn tee_attribute_boolean_from_value(value: B256) -> Option<bool> {
    if value == B256::ZERO {
        Some(false)
    } else if value == B256::with_last_byte(1) {
        Some(true)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub struct AppRef {
    pub name: String,
    pub version: String,
}

impl AppRef {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn id(&self, domain: &str) -> B256 {
        // Compute workloadId as keccak256(abi.encode(name, version))
        keccak256((keccak256(domain), self.name.clone(), self.version.clone()).abi_encode_params())
    }
}

impl Serialize for AppRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AppRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl std::str::FromStr for AppRef {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        ensure!(
            parts.len() == 2,
            "Expected format 'name:version', got '{}'",
            s
        );
        Ok(AppRef {
            name: parts[0].to_string(),
            version: parts[1].to_string(),
        })
    }
}

impl std::fmt::Display for AppRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.version)
    }
}

/// Request for registerSession
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSessionRequest {
    /// Attestation evidence from CVM agent
    pub evidence: AttestationEvidence,
    /// Workload ID (bytes32 hex)
    pub workload_id: B256,
    /// Base image ID (bytes32 hex)
    pub base_image_id: B256,
    /// Platform profile ID (bytes32 hex)
    pub platform_profile_id: B256,
    /// Measurement variant ID (bytes32 hex)
    pub variant_id: B256,
    /// Signature expiration timestamp (unix seconds)
    pub op_expires_at: u64,
    /// Owner's public identity
    pub owner_identity: PublicIdentity,
    /// Owner's signature over the registration message (pre-signed)
    pub owner_signature: Bytes,
}

/// Response from registerSession
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSessionResponse {
    /// The registered session ID
    pub session_id: B256,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Request for rotateKey
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyRequest {
    /// Old session ID to rotate from
    pub old_session_id: B256,
    /// Hash of the original TEE report data (keccak256)
    pub tee_report_bytes_hash: B256,
    /// Rotation evidence from CVM agent
    pub rotation_evidence: SessionKeyRotationEvidence,
    /// Signature expiration timestamp (unix seconds)
    pub op_expires_at: u64,
    /// Owner's public identity
    pub owner_identity: PublicIdentity,
    /// Owner's signature over the rotation message (pre-signed)
    pub owner_signature: Bytes,
}

/// Response from rotateKey
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyResponse {
    /// The new session ID after rotation
    pub new_session_id: B256,
    /// Transaction hash
    pub tx_hash: B256,
}

/// Request for renewSession.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewSessionRequest {
    pub old_session_id: B256,
    pub new_evidence: AttestationEvidence,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub platform_profile_id: B256,
    pub measurement_variant_id: B256,
    pub renewal_authorization: SessionRenewalAuthorization,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Bytes,
}

/// Request for recoverSession.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverSessionRequest {
    pub old_session_id: B256,
    pub new_evidence: AttestationEvidence,
    pub workload_id: B256,
    pub base_image_id: B256,
    pub platform_profile_id: B256,
    pub measurement_variant_id: B256,
    pub op_expires_at: u64,
    pub owner_identity: PublicIdentity,
    pub owner_signature: Bytes,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleSessionResponse {
    pub new_session_id: B256,
    pub tx_hash: B256,
}

#[cfg(test)]
mod tee_attribute_tests {
    use super::{
        TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME,
        TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY, TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME,
        TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY, TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME,
        tee_attribute_boolean_from_value, tee_attribute_boolean_value, tee_attribute_key,
        tee_attribute_name,
    };
    use alloy::primitives::B256;

    #[test]
    fn keys_match_contract_vectors() {
        assert_eq!(
            *TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY,
            "e96023946a6ad61275cb45a796a2905e3d923139ce33b7734f3bea4eec3d72cd"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            *TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY,
            "e3517680fe2d4f15751da85b0400ea909bb3d5ae76232c10a6c447031d6389b9"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            *TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY,
            "9090b994ea4098b565ee0da01c4bcaa083a5bfb19c0a797c7ffe3de7ce0251e1"
                .parse::<B256>()
                .unwrap()
        );
    }

    #[test]
    fn name_and_boolean_helpers_are_exact() {
        for (name, key) in [
            (
                TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME,
                *TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY,
            ),
            (
                TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME,
                *TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY,
            ),
            (
                TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME,
                *TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY,
            ),
        ] {
            assert_eq!(tee_attribute_key(name), Some(key));
            assert_eq!(tee_attribute_name(key), Some(name));
        }
        assert_eq!(tee_attribute_key("atakit.attestation.v1.tee.unknown"), None);
        assert_eq!(tee_attribute_name(B256::repeat_byte(0xff)), None);
        assert_eq!(tee_attribute_boolean_value(false), B256::ZERO);
        assert_eq!(tee_attribute_boolean_value(true), B256::with_last_byte(1));
        assert_eq!(tee_attribute_boolean_from_value(B256::ZERO), Some(false));
        assert_eq!(
            tee_attribute_boolean_from_value(B256::with_last_byte(1)),
            Some(true)
        );
        assert_eq!(
            tee_attribute_boolean_from_value(B256::with_last_byte(2)),
            None
        );
    }
}
