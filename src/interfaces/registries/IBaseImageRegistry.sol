// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {BaseImageSpec, PlatformProfile, MeasurementVariant, PublicIdentity} from "../../types/Common.sol";

/// @dev implements mapping (bytes32 baseImageId => BaseImageSpecStorage)
struct BaseImageSpecStorage {
    bool exists;
    BaseImageSpec spec;
    bytes32[] platformProfileIds;
}

/// @dev implements mapping (bytes32 platformProfileId => PlatformProfileStorage)
struct PlatformProfileStorage {
    bool exists;
    PlatformProfile profile;
    bytes32[] variantKeys;
}

/// @dev implements mapping (bytes32 variantKey => MeasurementVariantStorage)
struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant variant;
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

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a new base image with platform profiles and measurement variants (immutable after registration)
    /// @dev Parallel array invariant: spec.profileIds[i] → platformProfiles[i] → measurementVariants[i][]
    /// @dev Inner parallel array: platformProfiles[i].variantKeys[j] → measurementVariants[i][j]
    /// @param spec Base image specification (name, version, uri, profileIds)
    /// @param platformProfiles Platform-specific profiles (invariants, attributes, variantKeys) - must match spec.profileIds length
    /// @param measurementVariants Machine-type-specific PCR overrides - measurementVariants[i].length must equal platformProfiles[i].variantKeys.length
    /// @param ownerIdentity The public key identity of the base image owner
    /// @param ownerSignature Signature over the base image registration data by ownerIdentity
    /// @return baseImageId The unique identifier for the registered base image (domain-separated hash)
    function registerBaseImage(
        BaseImageSpec calldata spec,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 baseImageId);

    /// @notice Deactivate a base image (soft delete)
    /// @param baseImageId The base image identifier
    /// @param ownerIdentity The public key identity of the base image owner
    /// @param ownerSignature Signature over the deactivation request by ownerIdentity
    function deactivateBaseImage(
        bytes32 baseImageId,
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

    /// @notice Check if a base image is active
    /// @param baseImageId The base image identifier
    /// @return True if the base image is active
    function isBaseImageActive(bytes32 baseImageId) external view returns (bool);

    /// @notice Check if a variant exists
    /// @param baseImageId The base image identifier
    /// @param variantId The variant identifier
    /// @return True if the variant exists
    function hasVariant(bytes32 baseImageId, bytes32 variantId) external view returns (bool);
}
