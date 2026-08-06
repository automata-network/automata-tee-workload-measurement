// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ============================================================================
// Verification & Access Control
// ============================================================================

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
struct PcrSpec256 {
    /// @dev PCR index (0-23 per TPM 2.0 specification)
    uint8 pcrIndex;
    /// @dev Canonical ABI encoding selected and interpreted only by the TPM verifier.
    ///      The first ABI word is the uint16 comparison type. Remaining words use the
    ///      exact type-specific encoding defined by the canonical PCR policy specification.
    bytes comparison;
}

/// @notice SHA-384 PCR policy rule. Digest bytes use normal byte order.
struct PcrSpec384 {
    uint8 pcrIndex;
    /// @dev Canonical ABI encoding selected and interpreted only by the TPM verifier.
    bytes comparison;
}

/// @notice One named block of PCR policy comparison specifications.
/// @dev Policy specifications are kept distinct from measured PcrValue256 and
///      PcrValue384 evidence. Both arrays are strictly sorted by pcrIndex.
struct PcrPolicyBlock {
    PcrSpec256[] pcrSpecs256;
    PcrSpec384[] pcrSpecs384;
}

/// @notice Stored commitment and exact TPM selection bitmaps for one policy block.
struct PcrPolicyBlockMetadata {
    bytes32 blockHash;
    bytes3 pcrSelectBitmap256;
    bytes3 pcrSelectBitmap384;
}

/// @notice Normalized TPM Quote PCR selection and its exact signed digest.
struct PcrCommitment {
    bytes32 pcrSelect;
    bytes32 pcrDigest;
}

/// @notice PCR policy bank or banks evaluated for one platform profile.
enum PcrBankSelection {
    Sha256,
    Sha384,
    Sha256AndSha384
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
    /// @dev Rules for indices the parent profile leaves unpinned.
    PcrPolicyBlock variantPcrPolicy;
    /// @dev Machine-type-specific attributes (e.g., "machine_series": "n2d", "gpu": "nvidia-t4")
    Attribute[] attributes;
}

/// @notice Platform profile defining cloud provider and TEE configuration (storage struct)
/// @dev implements mapping (bytes32 platformProfileId => PlatformProfileStorage)
/// @dev variants are stored separately, indexed by (baseImageId, profileId, variantKey)
struct PlatformProfile {
    /// @dev Human-readable platform profile name (e.g., "azure-tdx-westus2")
    string name;
    /// @dev Policy bank or banks evaluated for this platform.
    PcrBankSelection pcrBankSelection;
    /// @dev PCR rules constant across all machine types in this platform.
    PcrPolicyBlock invariantPcrPolicy;
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
    /// @dev Workload PCR policy rules.
    PcrPolicyBlock workloadPcrPolicy;
}

struct ResolvedPcrPolicy {
    bytes32 workloadId;
    bytes32 baseImageId;
    bytes32 platformProfileId;
    bytes32 measurementVariantId;
    PcrBankSelection pcrBankSelection;
    PcrPolicyBlock invariantPcrPolicy;
    PcrPolicyBlock variantPcrPolicy;
    PcrPolicyBlock workloadPcrPolicy;
}

/// @notice Exact named PCR policy blocks evaluated for one TPM Quote verification.
/// @dev Duplicate PCR indexes across blocks are allowed. Every rule is evaluated.
struct TpmVerificationRequest {
    PcrBankSelection pcrBankSelection;
    PcrPolicyBlock invariantPcrPolicy;
    PcrPolicyBlock variantPcrPolicy;
    PcrPolicyBlock workloadPcrPolicy;
    PcrPolicyBlock providerPcrPolicy;
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
