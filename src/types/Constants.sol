// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ============================================================================
// Domain Constants
// ============================================================================

/// @dev Domain separator for public identity fingerprint computation (prevents cross-domain replay)
bytes32 constant KEY_DOMAIN = keccak256("KEY_RESOLVER_V1");
/// @dev Domain separator for session ID computation
bytes32 constant SESSION_DOMAIN = keccak256("CVM_SESSION_V1");
/// @dev Domain separator for session key delegation signatures (TPM key → session key)
bytes32 constant DELEGATION_DOMAIN = keccak256("CVM_SESSION_KEY_DELEGATION");
/// @dev Domain separator for cheap session key rotation authorization (old TPM key → new keys)
bytes32 constant SESSION_ROTATE_KEY_DOMAIN = keccak256("CVM_SESSION_ROTATE_KEY_V1");
/// @dev Domain separator for full session renewal authorization (old TPM key → successor evidence)
bytes32 constant SESSION_RENEW_DOMAIN = keccak256("CVM_SESSION_RENEW_V1");
/// @dev Domain separator for base image ID computation
bytes32 constant BASEIMAGE_DOMAIN = keccak256("CVM_BASEIMAGE_V1");
/// @dev Domain separator for platform profile ID computation
bytes32 constant PLATFORM_PROFILE_DOMAIN = keccak256("CVM_PLATFORM_PROFILE_V1");
/// @dev Domain separator for measurement variant key computation
bytes32 constant PLATFORM_VARIANT_DOMAIN = keccak256("CVM_PLATFORM_VARIANT_V1");
/// @dev Domain separator for workload ID computation
bytes32 constant WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1");
/// @dev Domain separator for TPM quote extraData nonce binding (used by SessionRegistry)
bytes32 constant SESSION_NONCE_DOMAIN = keccak256("CVM_SESSION_REG_NONCE_V1");
/// @dev Domain separator for one named PCR policy block.
bytes32 constant PCR_POLICY_BLOCK_DOMAIN = keccak256("CVM_PCR_POLICY_BLOCK_V1");
/// @dev Domain separator for the four named PCR policy block hashes.
bytes32 constant TPM_POLICY_COMMITMENT_DOMAIN = keccak256("CVM_TPM_POLICY_COMMITMENT_V1");
/// @dev Domain separator for the AWS AMD SEV-SNP REPORT_DATA PCR commitment hash.
bytes32 constant AWS_REPORT_DATA_PCR_COMMITMENT_DOMAIN = keccak256("CVM_AWS_REPORT_DATA_PCR_COMMITMENT_V1");

// ============================================================================
// Verified TEE Attribute Constants
// ============================================================================

/// @dev Reserved base-image and workload attribute keys.
bytes32 constant TEE_ATTRIBUTE_INTEL_TDX_DEBUG = keccak256("atakit.attestation.v1.tee.intel-tdx.debug.enabled");
bytes32 constant TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG = keccak256("atakit.attestation.v1.tee.amd-sev-snp.debug.enabled");
bytes32 constant TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA =
    keccak256("atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled");
bytes32 constant TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED =
    keccak256("atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed");
bytes32 constant TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM = keccak256("atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum");
bytes32 constant TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY =
    keccak256("atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy");

/// @dev Canonical Boolean attribute values.
bytes32 constant TEE_ATTRIBUTE_FALSE = bytes32(0);
bytes32 constant TEE_ATTRIBUTE_TRUE = bytes32(uint256(1));

/// @dev Stable internal bits returned in TeeVerificationResult.enabledTeeAttributes.
uint256 constant TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT = uint256(1) << 0;
uint256 constant TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT = uint256(1) << 1;
uint256 constant TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT = uint256(1) << 2;

/// @dev Intel DCAP TCB status values are represented as one-hot bits.
uint256 constant TDX_TCB_STATUS_OK = uint256(1) << 0;
uint256 constant TDX_TCB_STATUS_SW_HARDENING_NEEDED = uint256(1) << 1;
uint256 constant TDX_TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED = uint256(1) << 2;
uint256 constant TDX_TCB_STATUS_CONFIGURATION_NEEDED = uint256(1) << 3;
uint256 constant TDX_TCB_STATUS_OUT_OF_DATE = uint256(1) << 4;
uint256 constant TDX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED = uint256(1) << 5;
uint256 constant TDX_TCB_STATUS_RELAUNCH_ADVISED = uint256(1) << 8;
uint256 constant TDX_TCB_STATUS_RELAUNCH_ADVISED_CONFIGURATION_NEEDED = uint256(1) << 9;
uint256 constant TDX_TCB_STATUS_CONFIGURABLE_MASK = uint256(0x33f);

/// @dev AMD SEV-SNP PLATFORM_INFO bits supported by the current policy.
uint64 constant SNP_PLATFORM_INFO_SMT_EN = uint64(1) << 0;
uint64 constant SNP_PLATFORM_INFO_TSME_EN = uint64(1) << 1;
uint64 constant SNP_PLATFORM_INFO_ECC_EN = uint64(1) << 2;
uint64 constant SNP_PLATFORM_INFO_RAPL_DIS = uint64(1) << 3;
uint64 constant SNP_PLATFORM_INFO_CIPHERTEXT_HIDING_DRAM_EN = uint64(1) << 4;
uint64 constant SNP_PLATFORM_INFO_ALIAS_CHECK_COMPLETE = uint64(1) << 5;
uint64 constant SNP_PLATFORM_INFO_SUPPORTED_MASK = uint64(0x3f);

// ─── Operation Message Separators ──────────────────────────────────────
/// @dev Message separator for base image registration message signatures
bytes32 constant BASEIMAGE_REGISTER_MSG = keccak256("CVM_MSG_BASEIMAGE_REGISTER_V1");
/// @dev Message separator for base image deactivation message signatures
bytes32 constant BASEIMAGE_DEACTIVATE_MSG = keccak256("CVM_MSG_BASEIMAGE_DEACTIVATE_V1");
/// @dev Message separator for base image update message signatures
bytes32 constant BASEIMAGE_UPDATE_MSG = keccak256("CVM_MSG_BASEIMAGE_UPDATE_V1");
/// @dev Message separator for workload registration message signatures
bytes32 constant WORKLOAD_REGISTER_MSG = keccak256("CVM_MSG_WORKLOAD_REGISTER_V1");
/// @dev Message separator for workload deactivation message signatures
bytes32 constant WORKLOAD_DEACTIVATE_MSG = keccak256("CVM_MSG_WORKLOAD_DEACTIVATE_V1");
/// @dev Message separator for session registration message signatures
bytes32 constant SESSION_REGISTER_MSG = keccak256("CVM_MSG_SESSION_REGISTER_V1");
/// @dev Message separator for session revocation message signatures
bytes32 constant SESSION_REVOKE_MSG = keccak256("CVM_MSG_SESSION_REVOKE_V1");
/// @dev Message separator for cheap session-key rotation owner signatures
bytes32 constant SESSION_ROTATE_KEY_MSG = keccak256("CVM_MSG_SESSION_ROTATE_KEY_V1");
/// @dev Message separator for full session renewal owner signatures
bytes32 constant SESSION_RENEW_MSG = keccak256("CVM_MSG_SESSION_RENEW_V1");
/// @dev Message separator for owner-authorized recovery signatures
bytes32 constant SESSION_RECOVER_MSG = keccak256("CVM_MSG_SESSION_RECOVER_V1");

// ============================================================================
// Algorithm Constants (JWT Standard Names - RFC 7518)
// ============================================================================

uint8 constant ALGO_ID_NULL = 0;
uint8 constant ALGO_ID_RS256 = 1; // RSA PKCS#1 v1.5 with SHA-256
uint8 constant ALGO_ID_ES256 = 2; // ECDSA P-256 curve with SHA-256
uint8 constant ALGO_ID_ES256K = 3; // ECDSA secp256k1 curve with SHA-256
