use alloy::{
    primitives::{B256, Bytes, keccak256},
    sol_types::SolValue,
};
use anyhow::{bail, ensure};
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
pub const TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME: &str =
    "atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed";
pub const TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum";
pub const TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME: &str =
    "atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy";

pub static TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME));
pub static TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME));
pub static TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY: LazyLock<B256> =
    LazyLock::new(|| keccak256(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME));

pub const TDX_TCB_STATUS_NAMES: [(&str, u16); 8] = [
    ("ok", 1 << 0),
    ("sw-hardening-needed", 1 << 1),
    ("configuration-and-sw-hardening-needed", 1 << 2),
    ("configuration-needed", 1 << 3),
    ("out-of-date", 1 << 4),
    ("out-of-date-configuration-needed", 1 << 5),
    ("relaunch-advised", 1 << 8),
    ("relaunch-advised-configuration-needed", 1 << 9),
];
pub const TDX_TCB_STATUS_CONFIGURABLE_MASK: u16 = 0x33f;

pub fn tee_attribute_key(name: &str) -> Option<B256> {
    match name {
        TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME => Some(*TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY),
        TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME => Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY),
        TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME => {
            Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY)
        }
        TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME => {
            Some(*TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY)
        }
        TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME => {
            Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY)
        }
        TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME => {
            Some(*TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY)
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
    } else if key == *TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY {
        Some(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME)
    } else if key == *TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY {
        Some(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME)
    } else if key == *TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY {
        Some(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME)
    } else {
        None
    }
}

pub fn tdx_tcb_status_bit(name: &str) -> Option<u16> {
    TDX_TCB_STATUS_NAMES
        .iter()
        .find_map(|(candidate, bit)| (*candidate == name).then_some(*bit))
}

pub fn tdx_tcb_status_mask<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<u16> {
    let mut mask = 0u16;
    for name in names {
        let bit = tdx_tcb_status_bit(name)?;
        if mask & bit != 0 {
            return None;
        }
        mask |= bit;
    }
    ((mask & 1) != 0).then_some(mask)
}

pub fn tdx_tcb_status_names(mask: u16) -> Option<Vec<&'static str>> {
    if mask & 1 == 0 || mask & !TDX_TCB_STATUS_CONFIGURABLE_MASK != 0 {
        return None;
    }
    Some(
        TDX_TCB_STATUS_NAMES
            .iter()
            .filter_map(|(name, bit)| (mask & bit != 0).then_some(*name))
            .collect(),
    )
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

/// A publisher-qualified reference to a registered base image or workload.
///
/// The publisher is the owner fingerprint,
/// `keccak256(abi.encode(KEY_DOMAIN, identity.typeId, identity.key))`, and it is
/// part of the derived identifier rather than metadata beside it. Without it the
/// name space is flat and shared: a `WorkloadSpec.baseImageIds` entry would name
/// a name-and-version pair and nothing more, an identity anyone can claim to
/// speak for. On chain that gap is closed outside the identifier by registration
/// access control, but an offline verifier reading a signed archive reaches none
/// of that, so the binding has to live in the identifier itself.
///
/// One `AppRef` serves both registries, so base-image and workload identifiers
/// share this grammar by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRef {
    /// Owner fingerprint of the publisher that registered this name.
    pub publisher: B256,
    pub name: String,
    pub version: String,
}

impl AppRef {
    pub fn new(publisher: B256, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            publisher,
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn id(&self, domain: &str) -> B256 {
        keccak256(
            (
                keccak256(domain),
                self.publisher,
                self.name.clone(),
                self.version.clone(),
            )
                .abi_encode_params(),
        )
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

    /// Parse the canonical form `<publisher>/<name>:<version>` only.
    ///
    /// A two-part `name:version` reference is **rejected outright** rather than
    /// accepted with a zero or defaulted publisher. Tolerating the old form
    /// would let every existing manifest keep parsing while nothing was
    /// actually bound, so the change would ship without taking effect. There is
    /// no migration, so hard rejection costs nothing.
    ///
    /// Publisher aliases are not resolved here. This type has no business
    /// reading operator configuration, and a wire type's `FromStr` must be
    /// total and pure; expansion is a separate step in the command and
    /// configuration layer that runs before this parse.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((publisher, rest)) = s.split_once('/') else {
            bail!(
                "expected format '<publisher>/<name>:<version>', got '{}'; \
                 a reference without a publisher is no longer accepted",
                s
            );
        };
        ensure!(
            publisher.len() == 66 && publisher.starts_with("0x"),
            "publisher must be '0x' followed by 64 lowercase hexadecimal characters, got '{}'",
            publisher
        );
        ensure!(
            publisher[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "publisher must be lowercase hexadecimal, got '{}'",
            publisher
        );
        let publisher: B256 = publisher
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid publisher fingerprint: {error}"))?;
        let Some((name, version)) = rest.split_once(':') else {
            bail!(
                "expected format '<publisher>/<name>:<version>', got '{}'",
                s
            );
        };
        ensure!(!name.is_empty(), "name must not be empty in '{}'", s);
        ensure!(!version.is_empty(), "version must not be empty in '{}'", s);
        Ok(AppRef {
            publisher,
            name: name.to_string(),
            version: version.to_string(),
        })
    }
}

impl std::fmt::Display for AppRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The fingerprint is never truncated: it is the binding, and shortening
        // it reintroduces the collision this grammar removes.
        write!(f, "{}/{}:{}", self.publisher, self.name, self.version)
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
        TDX_TCB_STATUS_CONFIGURABLE_MASK, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_KEY,
        TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_NAME, TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_KEY,
        TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_NAME,
        TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
        TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
        TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY, TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME,
        TEE_ATTRIBUTE_INTEL_TDX_DEBUG_KEY, TEE_ATTRIBUTE_INTEL_TDX_DEBUG_NAME,
        TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
        TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME, tdx_tcb_status_mask, tdx_tcb_status_names,
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
        assert_eq!(
            *TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
            "bc505eab3cf5643bdf24f1dee86998cd93d05a297e4c34f5e8f37bba764a8116"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            *TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY,
            "15647616165618c3cfed2ab7f083f2f7eef7f57519e43d97ab220ff7860157d2"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            *TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
            "279fd9a317a2dc8dfeea12391ea795ac6c21ff52977c499f910f07a27afbed7d"
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
            (
                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_NAME,
                *TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED_KEY,
            ),
            (
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_NAME,
                *TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM_KEY,
            ),
            (
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_NAME,
                *TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY_KEY,
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

    #[test]
    fn tdx_tcb_status_masks_are_canonical() {
        assert_eq!(tdx_tcb_status_mask(["ok"]), Some(1));
        assert_eq!(
            tdx_tcb_status_mask(["ok", "sw-hardening-needed", "configuration-needed"]),
            Some(11)
        );
        assert_eq!(tdx_tcb_status_mask(["configuration-needed"]), None);
        assert_eq!(tdx_tcb_status_mask(["ok", "ok"]), None);
        assert_eq!(tdx_tcb_status_mask(["ok", "unknown"]), None);
        assert_eq!(
            tdx_tcb_status_names(TDX_TCB_STATUS_CONFIGURABLE_MASK)
                .unwrap()
                .len(),
            8
        );
        assert_eq!(tdx_tcb_status_names(0), None);
        assert_eq!(tdx_tcb_status_names(0x401), None);
    }
}

#[cfg(test)]
mod app_ref_tests {
    use super::AppRef;
    use alloy::primitives::{B256, b256};

    const PUBLISHER: B256 =
        b256!("9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f");

    fn canonical() -> String {
        format!("{PUBLISHER}/fedora-oci:v0.0.16")
    }

    /// The whole change depends on this. Accepting a two-part reference with a
    /// zero or defaulted publisher would let every existing manifest keep
    /// parsing while nothing was actually bound, and the change would ship
    /// without taking effect.
    #[test]
    fn a_reference_without_a_publisher_is_rejected() {
        for unqualified in [
            "fedora-oci:v0.0.16",
            "automata-linux:v0.2.8-debug",
            ":v1",
            "name:",
        ] {
            let error = unqualified
                .parse::<AppRef>()
                .expect_err("an unqualified reference must not parse");
            assert!(
                error.to_string().contains("publisher"),
                "the failure must say what is missing; got {error}"
            );
        }
    }

    #[test]
    fn the_canonical_form_round_trips() {
        let parsed: AppRef = canonical().parse().expect("canonical reference");
        assert_eq!(parsed.publisher, PUBLISHER);
        assert_eq!(parsed.name, "fedora-oci");
        assert_eq!(parsed.version, "v0.0.16");
        assert_eq!(parsed.to_string(), canonical());
    }

    /// The fingerprint is the binding, so a shortened one is refused rather
    /// than padded or accepted.
    #[test]
    fn a_truncated_or_malformed_publisher_is_rejected() {
        for bad in [
            "0x9f2c/name:v1",
            "9f2c1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f/name:v1",
            "0X9F2C1D3E4A5B6C7D8E9F0A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F/name:v1",
            "0xzzzc1d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f/name:v1",
        ] {
            assert!(
                bad.parse::<AppRef>().is_err(),
                "a malformed publisher must be rejected: {bad}"
            );
        }
    }

    /// The publisher is part of the identifier, not metadata beside it: the
    /// same name and version registered by two publishers are two identifiers.
    #[test]
    fn the_publisher_changes_the_identifier() {
        let mine = AppRef::new(PUBLISHER, "fedora-oci", "v0.0.16");
        let theirs = AppRef::new(B256::repeat_byte(0xab), "fedora-oci", "v0.0.16");
        assert_ne!(
            mine.id("CVM_BASEIMAGE_V1"),
            theirs.id("CVM_BASEIMAGE_V1"),
            "the same name under a different publisher must be a different identifier"
        );
    }

    /// One `AppRef` serves both registries, and the domain still separates them.
    #[test]
    fn the_domain_still_separates_the_two_registries() {
        let reference = AppRef::new(PUBLISHER, "shared-name", "v1");
        assert_ne!(
            reference.id("CVM_BASEIMAGE_V1"),
            reference.id("CVM_WORKLOAD_V1")
        );
    }

    #[test]
    fn serialization_uses_the_canonical_form() {
        let reference: AppRef = canonical().parse().unwrap();
        let encoded = serde_json::to_string(&reference).expect("serialize");
        assert_eq!(encoded, format!("\"{}\"", canonical()));
        let decoded: AppRef = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, reference);
    }
}
