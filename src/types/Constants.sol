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
/// @dev Domain separator for base image ID computation
bytes32 constant BASEIMAGE_DOMAIN = keccak256("CVM_BASEIMAGE_V1");
/// @dev Domain separator for platform profile ID computation
bytes32 constant PLATFORM_PROFILE_DOMAIN = keccak256("CVM_PLATFORM_PROFILE_V1");
/// @dev Domain separator for measurement variant key computation
bytes32 constant PLATFORM_VARIANT_DOMAIN = keccak256("CVM_PLATFORM_VARIANT_V1");
/// @dev Domain separator for workload ID computation
bytes32 constant WORKLOAD_DOMAIN = keccak256("CVM_WORKLOAD_V1");

// ============================================================================
// Algorithm Constants
// ============================================================================

uint8 constant ALGO_ID_RSA_2048 = 1;
uint8 constant ALGO_ID_RSA_4096 = 2;
uint8 constant ALGO_ID_ECDSA_SECP256R1 = 3;
uint8 constant ALGO_ID_ECDSA_SECP256K1 = 4;
uint8 constant ALGO_ID_ECDSA_SECP384R1 = 5;
uint8 constant ALGO_ID_ED25519 = 6;