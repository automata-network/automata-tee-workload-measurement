use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    signers::{Signer, local::PrivateKeySigner},
    sol_types::SolValue,
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Domain constant for key fingerprint computation (must match Constants.sol)
static KEY_DOMAIN: LazyLock<B256> = LazyLock::new(|| keccak256(b"KEY_RESOLVER_V1"));

alloy::contract! {
    WorkloadRegistry => "./contract_artifacts/WorkloadRegistry.sol/WorkloadRegistry.json",
    SessionRegistry => "./contract_artifacts/SessionRegistry.sol/SessionRegistry.json",
    BaseImageRegistry => "./contract_artifacts/BaseImageRegistry.sol/BaseImageRegistry.json",
    TpmAttestation => "./contract_artifacts/TpmAttestation.sol/TpmAttestation.json",
    TpmVerifier => "./contract_artifacts/TpmVerifier.sol/TpmVerifier.json",
    TeeVerifier => "./contract_artifacts/TeeVerifier.sol/TeeVerifier.json",
    AkCollateralVerifier => "./contract_artifacts/AkCollateralVerifier.sol/AkCollateralVerifier.json",
}

// Define TpmQuoteReport for ABI decoding (not exported in SessionRegistry ABI)
alloy::sol! {
    struct TpmQuoteReport {
        bytes tpm2bAttest;
        bytes tpmSignature;
        PcrValue[] pcrValues;
    }

    struct PcrValue {
        uint8 pcrIndex;
        bytes32 value;
        bytes32[] eventLogHashes;
    }

    // Mirrors Evidence.sol `ZkProof`. SnpZkProof is ABI-forward-compatible (same first
    // two fields), so this decodes both and `output` is read correctly either way.
    struct ZkProof {
        bytes output;
        bytes proofBytes;
    }
}

/// Algorithm ID for public key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgoId {
    /// Null/invalid algorithm
    Null = 0,
    /// RSA PKCS#1 v1.5 with SHA-256
    Rs256 = 1,
    /// ECDSA P-256 curve with SHA-256
    Es256 = 2,
    /// ECDSA secp256k1 curve with SHA-256
    Es256K = 3,
}

/// Public identity for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicIdentity {
    pub type_id: u8,
    pub key: Bytes,
}

impl PublicIdentity {
    pub fn secp256k1(signer: &PrivateKeySigner) -> Self {
        let verifying_key = signer.credential().verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false); // false = uncompressed
        let public_key_bytes = encoded_point.as_bytes(); // 65 bytes: 0x04 || x || y

        PublicIdentity {
            type_id: AlgoId::Es256K as _,
            key: public_key_bytes.to_vec().into(),
        }
    }

    pub fn is_secp256k1(&self) -> bool {
        self.type_id == AlgoId::Es256K as u8
    }

    pub fn is_secp256r1(&self) -> bool {
        self.type_id == AlgoId::Es256 as u8
    }

    pub fn is_rsa(&self) -> bool {
        self.type_id == AlgoId::Rs256 as u8
    }

    pub fn secp256k1_address(&self) -> Option<Address> {
        if !self.is_secp256k1() {
            return None;
        }
        // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey[1..])
        let pubkey_bytes = &self.key;
        if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
            return None; // Invalid uncompressed key format
        }
        let hash = keccak256(&pubkey_bytes[1..]); // Skip the 0x04 prefix
        Some(Address::from_slice(&hash[12..])) // Take the last 20 bytes
    }

    /// Compute key fingerprint as defined in LibKey.sol:
    /// fingerprint = keccak256(abi.encode(KEY_DOMAIN, typeId, key))
    pub fn fingerprint(&self) -> B256 {
        // abi.encode(bytes32 domain, uint8 typeId, bytes key)
        // For dynamic types like bytes, abi.encode uses:
        // - 32 bytes: domain
        // - 32 bytes: typeId (right-aligned)
        // - 32 bytes: offset to bytes data (= 96)
        // - 32 bytes: bytes length
        // - N bytes: bytes data (padded to 32-byte boundary)
        let key_len = self.key.len();
        let padded_key_len = ((key_len + 31) / 32) * 32;
        let total_len = 32 + 32 + 32 + 32 + padded_key_len;

        let mut encoded = vec![0u8; total_len];
        encoded[0..32].copy_from_slice(KEY_DOMAIN.as_slice());
        encoded[63] = self.type_id as u8; // uint8 right-aligned in 32 bytes
        // offset to bytes data = 96 (3 * 32)
        encoded[95] = 96;
        // bytes length
        encoded[127] = key_len as u8;
        // bytes data
        encoded[128..128 + key_len].copy_from_slice(&self.key);

        keccak256(&encoded)
    }
}

impl From<PublicIdentity> for BaseImageRegistry::PublicIdentity {
    fn from(identity: PublicIdentity) -> Self {
        BaseImageRegistry::PublicIdentity {
            typeId: identity.type_id,
            key: identity.key,
        }
    }
}

impl From<PublicIdentity> for WorkloadRegistry::PublicIdentity {
    fn from(identity: PublicIdentity) -> Self {
        WorkloadRegistry::PublicIdentity {
            typeId: identity.type_id,
            key: identity.key,
        }
    }
}

impl From<PublicIdentity> for SessionRegistry::PublicIdentity {
    fn from(identity: PublicIdentity) -> Self {
        SessionRegistry::PublicIdentity {
            typeId: identity.type_id,
            key: identity.key,
        }
    }
}

/// Sign ABI-encoded data with SHA256 hash.
///
/// This matches the contract's message construction:
/// ```solidity
/// sha256(abi.encode(...))
/// ```
///
/// The caller should include the domain separator in the payload.
pub async fn sign_message<T>(payload: &T, signer: &PrivateKeySigner) -> anyhow::Result<Bytes>
where
    T: SolValue,
    for<'a> <T::SolType as alloy::sol_types::SolType>::Token<'a>:
        alloy::sol_types::abi::token::TokenSeq<'a>,
{
    let encoded = payload.abi_encode_params();

    // SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    let result = hasher.finalize();
    let message_hash = B256::from_slice(&result);

    // Sign the hash
    let signature = signer
        .sign_hash(&message_hash)
        .await
        .context("Failed to sign message")?;

    // Build signature bytes (65 bytes: r || s || v)
    let mut sig_bytes = Vec::with_capacity(65);
    sig_bytes.extend_from_slice(&signature.r().to_be_bytes::<32>());
    sig_bytes.extend_from_slice(&signature.s().to_be_bytes::<32>());
    sig_bytes.push(if signature.v() { 28u8 } else { 27u8 });

    Ok(sig_bytes.into())
}

/// Compute expiration timestamp as `now + offset_secs`.
pub fn expire_at(offset_secs: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + offset_secs
}

/// Attestation evidence for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationEvidence {
    pub tee_report: TeeReport,
    pub tpm_quote_report: TpmReport,
    pub tpm_certify_report: TpmReport,
    pub ak_pub_collateral: AkPubCollateral,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentity,
}

impl From<AttestationEvidence> for SessionRegistry::AttestationEvidence {
    fn from(data: AttestationEvidence) -> Self {
        unsafe { std::mem::transmute(data) }
    }
}

/// TEE report data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeReport {
    pub verification_backend_type: u8,
    pub tee_type: u8,
    pub data: Bytes,
}

impl From<TeeReport> for SessionRegistry::TeeReport {
    fn from(data: TeeReport) -> Self {
        unsafe { std::mem::transmute(data) }
    }
}

/// TPM report data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmReport {
    pub verification_backend_type: u8,
    pub tpm_report_type: u8,
    pub data: Bytes,
}

impl From<TpmReport> for SessionRegistry::TpmReport {
    fn from(data: TpmReport) -> Self {
        unsafe { std::mem::transmute(data) }
    }
}

/// AK pub collateral data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AkPubCollateral {
    pub ak_pub_collateral_type: u8,
    pub data: Bytes,
}

impl From<AkPubCollateral> for SessionRegistry::AkPubCollateral {
    fn from(data: AkPubCollateral) -> Self {
        unsafe { std::mem::transmute(data) }
    }
}

/// Session rotation evidence for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRotationEvidence {
    pub tpm_quote_report: TpmReport,
    pub tpm_certify_report: TpmReport,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentity,
    pub rotation_signature: Bytes,
    pub old_tpm_signing_key: PublicIdentity,
    pub ak_pub: PublicIdentity,
}

impl From<SessionRotationEvidence> for SessionRegistry::SessionRotationEvidence {
    fn from(data: SessionRotationEvidence) -> Self {
        unsafe { std::mem::transmute(data) }
    }
}

pub type BaseImageSpec = BaseImageRegistry::BaseImageSpec;
pub type PlatformProfile = BaseImageRegistry::PlatformProfile;
pub type MeasurementVariant = BaseImageRegistry::MeasurementVariant;
