// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {BaseImageSpec, PlatformProfile, MeasurementVariant, PublicIdentity} from "../../types/Common.sol";

/// @dev implements mapping (bytes32 baseImageId => BaseImageSpecStorage)
/// @dev STORAGE LAYOUT IS LOAD-BEARING for off-chain consumers. The Rust client crate
///      `crates/automata-tee-workload-measurement/src/base_image_registry.rs::get_hierarchy`
///      reads `platformProfileIds` directly via `eth_getStorageAt` at the hard-coded
///      sub-slot offset +5 from the per-entry storage base (the `BaseImageSpec spec`
///      member occupies offsets 2..4 because it has three `string` fields). Reordering
///      fields, inserting new fields, or changing the type of any existing field will
///      silently break off-chain enumeration with no compile-time signal on either
///      side. If you must change the layout, update both this struct AND the offset
///      constant in the Rust crate in the same atomic change.
struct BaseImageSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    BaseImageSpec spec;
    bytes32[] platformProfileIds;
}

/// @dev implements mapping (bytes32 platformProfileId => PlatformProfileStorage)
/// @dev STORAGE LAYOUT IS LOAD-BEARING — same caveat as BaseImageSpecStorage. The Rust
///      `get_hierarchy` walker reads `variantIds` directly at sub-slot offset +4 from
///      the per-entry storage base (the `PlatformProfile platformProfile` member
///      occupies offsets 1..3: one `string name` plus two dynamic-array headers).
///      Reorders silently break off-chain enumeration.
struct PlatformProfileStorage {
    bool exists;
    PlatformProfile platformProfile;
    bytes32[] variantIds;
}

/// @dev implements mapping (bytes32 variantKey => MeasurementVariantStorage)
struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant measurementVariant;
}

interface IBaseImageRegistry {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a new base image is registered
    /// @param baseImageId Computed identifier for the base image
    /// @param owner Owner fingerprint (bytes32 encoding of PublicIdentity fingerprint)
    /// @param name Human-readable base image name
    /// @param version Semantic version string
    event BaseImageRegistered(bytes32 indexed baseImageId, bytes32 indexed owner, string name, string version);

    /// @notice Emitted when a base image is deactivated (soft delete)
    /// @param baseImageId The base image identifier
    /// @param owner The base image owner fingerprint
    event BaseImageDeactivated(bytes32 indexed baseImageId, bytes32 indexed owner);

    /// @notice Emitted when a platform profile is registered for a base image
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param name Human-readable platform profile name (e.g., "azure-tdx-westus2")
    event PlatformProfileRegistered(bytes32 indexed baseImageId, bytes32 indexed platformProfileId, string name);

    /// @notice Emitted when a measurement variant is registered for a platform profile
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The measurement variant identifier (computed from variant name)
    /// @param name Human-readable variant name (e.g., machine type)
    event MeasurementVariantRegistered(bytes32 indexed platformProfileId, bytes32 indexed variantId, string name);

    /// @notice Emitted when platform variants are added/updated on an existing base image
    /// @param baseImageId The base image identifier
    /// @param owner The base image owner fingerprint
    event BaseImageUpdated(bytes32 indexed baseImageId, bytes32 indexed owner);

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a new base image with platform profiles and measurement variants (immutable after registration)
    /// @dev Parallel array invariant: spec.profileIds[i] → platformProfiles[i] → measurementVariants[i][]
    /// @dev Inner parallel array: platformProfiles[i].variantIds[j] → measurementVariants[i][j]
    /// @param spec Base image specification (name, version, uri, profileIds)
    /// @param platformProfiles Platform-specific profiles (invariants, attributes, variantIds) - must match spec.profileIds length
    /// @param measurementVariants Machine-type-specific PCR overrides - measurementVariants[i].length must equal platformProfiles[i].variantIds.length
    /// @param opExpiresAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the base image owner
    /// @param ownerSignature Signature over the base image registration data by ownerIdentity
    /// @return baseImageId The unique identifier for the registered base image (domain-separated hash)
    function registerBaseImage(
        BaseImageSpec calldata spec,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 baseImageId);

    /// @notice Deactivate a base image (soft delete)
    /// @param baseImageId The base image identifier
    /// @param opExpiresAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the base image owner
    /// @param ownerSignature Signature over the deactivation request by ownerIdentity
    function deactivateBaseImage(
        bytes32 baseImageId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Add or update platform profiles and measurement variants on an existing base image
    /// @dev Additive/upsert semantics: new profiles/variants are added, existing ones (same name → same ID) are overwritten.
    ///      Unmentioned profiles/variants remain untouched. Updates are blocked on revoked base images.
    /// @param baseImageId The base image identifier to update
    /// @param platformProfiles Platform-specific profiles to add/update
    /// @param measurementVariants Machine-type-specific PCR overrides - measurementVariants[i].length corresponds to platformProfiles[i]
    /// @param opExpiresAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the base image owner
    /// @param ownerSignature Signature over the update data by ownerIdentity
    function addPlatformVariants(
        bytes32 baseImageId,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Get basic metadata for a base image
    /// @param baseImageId The base image identifier
    /// @return spec The base image specification
    function getBaseImage(bytes32 baseImageId) external view returns (BaseImageSpec memory spec);

    /// @notice Get platform profile details
    /// @param platformProfileId The platform profile identifier
    /// @return platformProfile The platform profile
    function getPlatformProfile(bytes32 platformProfileId)
        external
        view
        returns (PlatformProfile memory platformProfile);

    /// @notice Get a specific measurement variant
    /// @param variantId The variant identifier
    /// @return variant The measurement variant data
    function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory variant);

    /// @notice Get all three specs (base image, platform profile, variant) in one call
    /// @dev Used by SessionRegistry to efficiently fetch all required data for validation
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The variant identifier
    /// @return baseImage The base image specification
    /// @return platformProfile The platform profile
    /// @return variant The measurement variant
    function getVariant(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        external
        view
        returns (
            BaseImageSpec memory baseImage,
            PlatformProfile memory platformProfile,
            MeasurementVariant memory variant
        );

    /// @notice Get the owner fingerprint of a registered base image
    /// @dev Returns the keccak256 fingerprint computed from the owner's PublicIdentity
    ///      This fingerprint is used for ownership verification in deactivation and access control
    /// @param baseImageId The base image identifier
    /// @return The owner's identity fingerprint (bytes32)
    function getBaseImageOwner(bytes32 baseImageId) external view returns (bytes32);

    /// @notice Check if a base image is revoked
    /// @param baseImageId The base image identifier
    /// @return True if the base image is revoked
    function isBaseImageRevoked(bytes32 baseImageId) external view returns (bool);

    /// @notice Check if a measurement variant exists
    /// @param variantId The variant identifier
    /// @return True if the variant exists
    function hasVariant(bytes32 variantId) external view returns (bool);
}
