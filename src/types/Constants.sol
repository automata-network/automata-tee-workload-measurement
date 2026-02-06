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
/// @dev Domain separator for session key rotation authorization (old TPM key → new keys)
bytes32 constant ROTATION_DOMAIN = keccak256("CVM_SESSION_KEY_ROTATION");
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

// ─── Operation Message Separators ──────────────────────────────────────
/// @dev Message separator for base image registration message signatures
bytes32 constant BASEIMAGE_REGISTER_MSG = keccak256("CVM_MSG_BASEIMAGE_REGISTER_V1");
/// @dev Message separator for base image deactivation message signatures
bytes32 constant BASEIMAGE_DEACTIVATE_MSG = keccak256("CVM_MSG_BASEIMAGE_DEACTIVATE_V1");
/// @dev Message separator for workload registration message signatures
bytes32 constant WORKLOAD_REGISTER_MSG = keccak256("CVM_MSG_WORKLOAD_REGISTER_V1");
/// @dev Message separator for workload deactivation message signatures
bytes32 constant WORKLOAD_DEACTIVATE_MSG = keccak256("CVM_MSG_WORKLOAD_DEACTIVATE_V1");
/// @dev Message separator for session registration message signatures
bytes32 constant SESSION_REGISTER_MSG = keccak256("CVM_MSG_SESSION_REGISTER_V1");
/// @dev Message separator for session revocation message signatures
bytes32 constant SESSION_REVOKE_MSG = keccak256("CVM_MSG_SESSION_REVOKE_V1");
/// @dev Message separator for session rotation message signatures
bytes32 constant SESSION_ROTATE_MSG = keccak256("CVM_MSG_SESSION_ROTATE_V1");

// ============================================================================
// Algorithm Constants (JWT Standard Names - RFC 7518)
// ============================================================================

uint8 constant ALGO_ID_NULL = 0;
uint8 constant ALGO_ID_RS256 = 1; // RSA PKCS#1 v1.5 with SHA-256
uint8 constant ALGO_ID_ES256 = 2; // ECDSA P-256 curve with SHA-256
uint8 constant ALGO_ID_ES256K = 3; // ECDSA secp256k1 curve with SHA-256
