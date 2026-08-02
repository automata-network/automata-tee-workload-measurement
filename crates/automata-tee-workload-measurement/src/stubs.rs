use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    signers::{Signer, local::PrivateKeySigner},
    sol_types::{SolType, SolValue, sol_data},
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Domain constant for key fingerprint computation (must match Constants.sol)
static KEY_DOMAIN: LazyLock<B256> = LazyLock::new(|| keccak256(b"KEY_RESOLVER_V1"));

type KeyFingerprintArgs = (sol_data::FixedBytes<32>, sol_data::Uint<8>, sol_data::Bytes);

alloy::contract! {
    WorkloadRegistry => "./contract_artifacts/WorkloadRegistry.sol/WorkloadRegistry.json",
    SessionRegistry => "./contract_artifacts/SessionRegistry.sol/SessionRegistry.json",
    BaseImageRegistry => "./contract_artifacts/BaseImageRegistry.sol/BaseImageRegistry.json",
    TpmAttestation => "./contract_artifacts/TpmAttestation.sol/TpmAttestation.json",
    TpmVerifier => "./contract_artifacts/TpmVerifier.sol/TpmVerifier.json",
    TeeVerifier => "./contract_artifacts/TeeVerifier.sol/TeeVerifier.json",
    AkCollateralVerifier => "./contract_artifacts/AkCollateralVerifier.sol/AkCollateralVerifier.json",
    AmdSnpSecurityPolicyRegistry => "./contract_artifacts/AmdSnpSecurityPolicyRegistry.sol/AmdSnpSecurityPolicyRegistry.json",
    ZkVerifierRegistry => "./contract_artifacts/ZkVerifierRegistry.sol/ZkVerifierRegistry.json",
}

alloy::sol! {
    struct Bytes48 {
        bytes32 first;
        bytes16 second;
    }

    struct PcrValue256 {
        uint8 pcrIndex;
        bytes32 value;
        bytes32[] eventLogHashes;
    }

    struct PcrValue384 {
        uint8 pcrIndex;
        Bytes48 value;
        Bytes48[] eventLogHashes;
    }

    struct TpmQuoteEvidence {
        bytes tpmsAttest;
        bytes tpmSignature;
        uint8 pcr0StartupLocality;
        PcrValue256[] pcrValues256;
        PcrValue384[] pcrValues384;
    }

    struct ProgramBoundZkProof {
        bytes32 programIdentifier;
        bytes output;
        bytes proofBytes;
    }

    struct AmdSevSnpZkEvidence {
        ProgramBoundZkProof proof;
        bytes rawReport;
    }

    struct TpmQuoteJournalV1 {
        bytes32 akPubFingerprint;
        bytes32 qualifyingData;
        bytes32 tpmSignatureHash;
        bytes32 sha256PolicyCommitment;
        bytes32 sha384PolicyCommitment;
        bytes32 sha256PcrBindingCommitment;
        bytes32 sha384PcrBindingCommitment;
        bytes32 sha256PcrSetCommitment;
        bytes32 sha384PcrSetCommitment;
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
        keccak256(KeyFingerprintArgs::abi_encode_params(&(
            *KEY_DOMAIN,
            self.type_id,
            self.key.clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{AlgoId, KEY_DOMAIN, PublicIdentity};
    use alloy::{
        primitives::{B256, Bytes, keccak256},
        sol_types::{SolType, sol_data},
    };

    type TestKeyFingerprintArgs = (sol_data::FixedBytes<32>, sol_data::Uint<8>, sol_data::Bytes);

    fn reference_fingerprint(type_id: u8, key: &[u8]) -> B256 {
        // Manual ABI reference for `abi.encode(bytes32,uint8,bytes)`.
        let key_len = key.len();
        let padded_key_len = key_len.div_ceil(32) * 32;
        let mut encoded = vec![0u8; 128 + padded_key_len];

        encoded[0..32].copy_from_slice(KEY_DOMAIN.as_slice());
        encoded[63] = type_id;
        encoded[95] = 96;
        encoded[120..128].copy_from_slice(&(key_len as u64).to_be_bytes());
        encoded[128..128 + key_len].copy_from_slice(key);

        keccak256(&encoded)
    }

    #[test]
    fn fingerprint_matches_abi_encoding_for_ec_key() {
        let identity = PublicIdentity {
            type_id: AlgoId::Es256K as u8,
            key: Bytes::from(vec![0x04; 65]),
        };

        assert_eq!(
            identity.fingerprint(),
            reference_fingerprint(identity.type_id, &identity.key)
        );
    }

    #[test]
    fn fingerprint_matches_abi_encoding_for_256_byte_key() {
        let identity = PublicIdentity {
            type_id: AlgoId::Rs256 as u8,
            key: Bytes::from((0u8..=255).collect::<Vec<_>>()),
        };

        let abi_encoded_hash = keccak256(TestKeyFingerprintArgs::abi_encode_params(&(
            *KEY_DOMAIN,
            identity.type_id,
            identity.key.clone(),
        )));
        let old_single_byte_length_hash = {
            let mut encoded = vec![0u8; 128 + identity.key.len()];
            encoded[0..32].copy_from_slice(KEY_DOMAIN.as_slice());
            encoded[63] = identity.type_id;
            encoded[95] = 96;
            encoded[127] = identity.key.len() as u8;
            encoded[128..].copy_from_slice(&identity.key);
            keccak256(&encoded)
        };

        assert_eq!(identity.fingerprint(), abi_encoded_hash);
        assert_eq!(
            identity.fingerprint(),
            reference_fingerprint(identity.type_id, &identity.key)
        );
        assert_ne!(identity.fingerprint(), old_single_byte_length_hash);
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
pub fn op_expires_at(offset_secs: u64) -> u64 {
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
    pub ak_pub: PublicIdentity,
    pub tpm_quote_report: TpmReport,
    pub tpm_certify_report: TpmReport,
    pub ak_pub_collateral: AkPubCollateral,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentity,
}

impl TryFrom<AttestationEvidence> for SessionRegistry::AttestationEvidence {
    type Error = anyhow::Error;

    fn try_from(data: AttestationEvidence) -> Result<Self> {
        Ok(Self {
            teeReport: data.tee_report.try_into()?,
            akPub: data.ak_pub.into(),
            tpmQuoteReport: data.tpm_quote_report.try_into()?,
            tpmCertifyReport: data.tpm_certify_report.try_into()?,
            akPubCollateral: data.ak_pub_collateral.try_into()?,
            sessionKeySignature: data.session_key_signature,
            sessionKey: data.session_key.into(),
        })
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

impl TryFrom<TeeReport> for SessionRegistry::TeeReport {
    type Error = anyhow::Error;

    fn try_from(data: TeeReport) -> Result<Self> {
        Ok(Self {
            verificationBackendType: verification_backend_type(data.verification_backend_type)?,
            teeType: tee_type(data.tee_type)?,
            data: data.data,
        })
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

impl TryFrom<TpmReport> for SessionRegistry::TpmReport {
    type Error = anyhow::Error;

    fn try_from(data: TpmReport) -> Result<Self> {
        Ok(Self {
            verificationBackendType: verification_backend_type(data.verification_backend_type)?,
            tpmReportType: tpm_report_type(data.tpm_report_type)?,
            data: data.data,
        })
    }
}

/// AK pub collateral data for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AkPubCollateral {
    pub ak_pub_collateral_type: u8,
    pub verification_backend_type: u8,
    pub data: Bytes,
}

impl TryFrom<AkPubCollateral> for SessionRegistry::AkPubCollateral {
    type Error = anyhow::Error;

    fn try_from(data: AkPubCollateral) -> Result<Self> {
        Ok(Self {
            akPubCollateralType: ak_pub_collateral_type(data.ak_pub_collateral_type)?,
            verificationBackendType: verification_backend_type(data.verification_backend_type)?,
            data: data.data,
        })
    }
}

/// Session rotation evidence for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKeyRotationEvidence {
    pub tpm_quote_report: TpmReport,
    pub tpm_certify_report: TpmReport,
    pub session_key_signature: Bytes,
    pub session_key: PublicIdentity,
    pub rotation_signature: Bytes,
    pub old_tpm_signing_key: PublicIdentity,
    pub ak_pub: PublicIdentity,
}

impl TryFrom<SessionKeyRotationEvidence> for SessionRegistry::SessionKeyRotationEvidence {
    type Error = anyhow::Error;

    fn try_from(data: SessionKeyRotationEvidence) -> Result<Self> {
        Ok(Self {
            tpmQuoteReport: data.tpm_quote_report.try_into()?,
            tpmCertifyReport: data.tpm_certify_report.try_into()?,
            sessionKeySignature: data.session_key_signature,
            sessionKey: data.session_key.into(),
            rotationSignature: data.rotation_signature,
            oldTpmSigningKey: data.old_tpm_signing_key.into(),
            akPub: data.ak_pub.into(),
        })
    }
}

/// Predecessor TPM-key authorization for a full session renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRenewalAuthorization {
    pub signature: Bytes,
    pub old_tpm_signing_key: PublicIdentity,
}

impl From<SessionRenewalAuthorization> for SessionRegistry::SessionRenewalAuthorization {
    fn from(data: SessionRenewalAuthorization) -> Self {
        Self {
            signature: data.signature,
            oldTpmSigningKey: data.old_tpm_signing_key.into(),
        }
    }
}

fn verification_backend_type(value: u8) -> Result<u8> {
    match value {
        0..=2 => Ok(value),
        _ => anyhow::bail!("Invalid VerificationBackendType value: {value}"),
    }
}

fn tee_type(value: u8) -> Result<u8> {
    match value {
        0..=1 => Ok(value),
        _ => anyhow::bail!("Invalid TEEType value: {value}"),
    }
}

fn tpm_report_type(value: u8) -> Result<u8> {
    match value {
        0..=1 => Ok(value),
        _ => anyhow::bail!("Invalid TpmReportType value: {value}"),
    }
}

fn ak_pub_collateral_type(value: u8) -> Result<u8> {
    match value {
        0..=2 => Ok(value),
        _ => anyhow::bail!("Invalid AkPubCollateralType value: {value}"),
    }
}

pub type BaseImageSpec = BaseImageRegistry::BaseImageSpec;
pub type PlatformProfile = BaseImageRegistry::PlatformProfile;
pub type MeasurementVariant = BaseImageRegistry::MeasurementVariant;
