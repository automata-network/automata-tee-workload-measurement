// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    Attribute,
    BaseImageSpec,
    MeasurementVariant,
    PcrBankSelection,
    PcrPolicyBlockMetadata,
    PlatformProfile,
    PublicIdentity
} from "../../types/Common.sol";

/// @dev implements mapping (bytes32 baseImageId => BaseImageSpecStorage)
struct BaseImageSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    BaseImageSpec spec;
    bytes32[] platformProfileIds;
}

/// @dev implements mapping (bytes32 platformProfileId => PlatformProfileStorage)
struct PlatformProfileStorage {
    bool exists;
    PlatformProfile platformProfile;
    PcrPolicyBlockMetadata invariantPcrPolicyMetadata;
    bytes32[] variantIds;
}

/// @dev implements mapping (bytes32 variantKey => MeasurementVariantStorage)
struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant measurementVariant;
    PcrPolicyBlockMetadata variantPcrPolicyMetadata;
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

    /// @notice Register a new base image with its initial platform profiles and measurement variants
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

    /// @notice Append platform profiles and measurement variants to an existing base image
    /// @dev New profiles and variants are added. An existing profile keeps its stored
    ///      metadata and may receive new variants. An existing variant ID reverts.
    ///      Unmentioned profiles and variants remain untouched. Updates are blocked
    ///      on revoked base images.
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

    /// @notice Get the platform profile identifiers registered under a base image
    /// @param baseImageId The base image identifier
    /// @return profileIds The platform profile identifiers in registration order
    function getPlatformProfileIds(bytes32 baseImageId) external view returns (bytes32[] memory profileIds);

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

    /// @notice Get the measurement variant identifiers registered under a platform profile
    /// @param platformProfileId The platform profile identifier
    /// @return variantIds The measurement variant identifiers in registration order
    function getMeasurementVariantIds(bytes32 platformProfileId) external view returns (bytes32[] memory variantIds);

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

    /// @notice Get the lightweight policy metadata and attributes for one valid hierarchy.
    /// @dev SessionRegistry uses this function for ZK verification without loading the stored
    ///      comparison blobs. The function enforces the same parent-child hierarchy as getVariant.
    function getVariantPolicyMetadata(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        external
        view
        returns (
            PcrBankSelection pcrBankSelection,
            Attribute[] memory platformAttributes,
            Attribute[] memory variantAttributes,
            PcrPolicyBlockMetadata memory invariantPcrPolicyMetadata,
            PcrPolicyBlockMetadata memory variantPcrPolicyMetadata
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

    /// @notice Returns true when only whitelisted owners may register or update base images.
    function registrationRestricted() external view returns (bool);

    /// @notice Check if a measurement variant exists
    /// @param variantId The variant identifier
    /// @return True if the variant exists
    function hasVariant(bytes32 variantId) external view returns (bool);
}
