// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ============================================================================
// Verification & Access Control
// ============================================================================

/// @notice PCR verification strategy for attestation measurement validation
enum PcrVerifyType {
    /// @dev Exact match: PCR final value must equal matchData[0]
    STATIC,
    /// @dev Required subset: matchData must occur in PCR events (any order)
    DYNAMIC_SUBSET,
    /// @dev Event subsequence: PCR events must contain matchData as an ordered subsequence
    DYNAMIC_SUBSEQUENCE
}

/// @notice Access control mode for workload base image policies
enum AccessMode {
    /// @dev No restrictions: all base images allowed
    ANY,
    /// @dev Block specific base images: baseImageSet contains blocked IDs
    BLACKLIST,
    /// @dev Allow only specific base images: baseImageSet contains allowed IDs
    WHITELIST
}

// ============================================================================
// Primitive Structs
// ============================================================================

/// @notice Generic public key identity representation
struct PublicIdentity {
    /// @dev Algorithm identifier
    uint8 typeId;
    /// @dev Public key bytes in algorithm-specific encoding (DER, X.509 SPKI, or raw coordinates)
    bytes key;
}

/// @notice Platform Configuration Register (PCR) specification for verification
struct PcrSpec {
    /// @dev PCR index (0-23 per TPM 2.0 specification)
    uint8 pcrIndex;
    /// @dev Verification strategy: STATIC (exact match), DYNAMIC_SUBSET (required unordered landmarks), DYNAMIC_SUBSEQUENCE (ordered landmarks)
    PcrVerifyType verifyType;
    /// @dev Match data interpretation depends on verifyType:
    ///      - STATIC: exactly one entry, matchData[0] = expected PCR final value
    ///      - DYNAMIC_SUBSET: matchData = set of required event hashes. Every matchData entry must
    ///        occur in the non-empty reported event log in any order; additional events are
    ///        permitted. Empty logs are rejected because no cumulative-hash verification occurs.
    ///      - DYNAMIC_SUBSEQUENCE: matchData = required event sequence (must appear in order in
    ///        a non-empty event log; empty event log is rejected for the same reason).
    bytes32[] matchData;
}

/// @notice Generic key-value attribute for metadata
struct Attribute {
    /// @dev Attribute identifier (typically keccak256 of attribute name)
    bytes32 key;
    /// @dev Attribute value (keccak256 hash for enums/strings, or raw bytes32 for fixed values)
    bytes32 value;
}

// ============================================================================
// Platform Registry Structs (BaseImageRegistry)
// ============================================================================

/// @notice Machine-type-specific PCR overrides within a platform profile (storage struct)
/// @dev Variants handle machine-specific differences (e.g., CPU architecture, GPU presence)
struct MeasurementVariant {
    /// @dev Human-readable machine type name (e.g., "n2d-standard-16", "Standard_D4s_v4")
    string name;
    /// @dev PCR specifications for indices the parent PlatformProfile leaves unpinned.
    ///      `overridePcrs` is a historical name kept for ABI/SDK compatibility: entries MUST be
    ///      disjoint from `PlatformProfile.invariants`. A profile invariant always holds — an
    ///      overlapping entry is rejected at registration (VariantOverridesInvariantPcr) and
    ///      again at session evaluation (PcrVariantOverridesInvariant), never applied.
    PcrSpec[] overridePcrs;
    /// @dev Machine-type-specific attributes (e.g., "machine_series": "n2d", "gpu": "nvidia-t4")
    Attribute[] attributes;
}

/// @notice Platform profile defining cloud provider and TEE configuration (storage struct)
/// @dev implements mapping (bytes32 platformProfileId => PlatformProfileStorage)
/// @dev variants are stored separately, indexed by (baseImageId, profileId, variantKey)
struct PlatformProfile {
    /// @dev Human-readable platform profile name (e.g., "azure-tdx-westus2")
    string name;
    /// @dev PCRs constant across all machine types in this platform (e.g., BIOS, bootloader, OS kernel)
    PcrSpec[] invariants;
    /// @dev Platform-wide attributes (e.g., "cloud": "Azure", "tee": "IntelTDX")
    Attribute[] attributes;
}

/// @notice Base image specification (immutable registration data)
/// @dev Base image = privileged OS environment (kernel, bootloader, CVM agent), measured by PCR 0-19
/// @dev platform profiles are stored separately, indexed by (baseImageId, profileId)
struct BaseImageSpec {
    /// @dev Human-readable image name (e.g., "ubuntu-confidential-22.04")
    string name;
    /// @dev Semantic version (e.g., "1.2.3")
    string version;
    /// @dev URI to detailed image metadata (e.g., IPFS hash, registry URL)
    string uri;
}

// ============================================================================
// Workload Registry Structs
// ============================================================================

/// @notice Attribute requirement for workload policy enforcement
struct AttributeRequirement {
    /// @dev Attribute key to check (e.g., keccak256("environment"))
    bytes32 key;
    /// @dev Allowed attribute values (empty array = any value accepted)
    ///      Example: [keccak256("production"), keccak256("staging")] restricts to those environments
    bytes32[] allowedValues;
}

/// @notice Workload specification (immutable registration data)
/// @dev Implementation note: owner/exists/active tracked separately in contract storage
/// @dev Workload = containerized application (unprivileged), measured by PCR 20-23
struct WorkloadSpec {
    /// @dev Human-readable workload name (e.g., "ml-training-service")
    string name;
    /// @dev Semantic version (e.g., "2.1.0")
    string version;
    /// @dev Session lifetime in seconds (0 means the SessionRegistry default of 30 days)
    uint64 sessionTtl;
    /// @dev Access control mode for base images:
    ///      - ANY: No restrictions (baseImageIds ignored)
    ///      - BLACKLIST: baseImageIds contains blocked base images
    ///      - WHITELIST: baseImageIds contains allowed base images
    AccessMode baseImageMode;
    /// @dev Base image identifiers (interpretation depends on baseImageMode)
    bytes32[] baseImageIds;
    /// @dev Attribute requirements (ALL must be satisfied for session registration)
    AttributeRequirement[] requirements;
    /// @dev PCR specifications for workload measurements (typically PCR 20-23)
    PcrSpec[] pcrs;
}

// ============================================================================
// Session Registry Structs
// ============================================================================

/// @notice Active CVM session state (cryptographic chain of trust)
/// @dev Session binds hardware attestation (TEE + vTPM) to operational session key
struct CVMSession {
    // Key Fingerprints (complete verification chain)
    bytes32 akPubKeyFingerprint; // Attestation Key (root of trust)
    bytes32 tpmSigningKeyFingerprint; // TPM Signing Key (extracted from quote)
    bytes32 sessionKeyFingerprint; // Session Key (operational key)

    // Context
    bytes32 baseImageId; // Associated platform image
    bytes32 workloadId; // Associated workload
    bytes32 platformProfileId; // Platform profile identifier
    bytes32 measurementVariantId; // Measurement variant identifier

    // Lifecycle
    uint64 registeredAt; // Registration timestamp
    uint64 sessionExpiresAt; // Absolute session expiration timestamp
}
