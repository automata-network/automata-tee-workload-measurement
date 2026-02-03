// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {BaseImageSpec, PlatformProfile, MeasurementVariant, PublicIdentity} from "./types/Common.sol";
import {BASEIMAGE_DOMAIN, PLATFORM_PROFILE_DOMAIN, PLATFORM_VARIANT_DOMAIN} from "./types/Constants.sol";
import {
    IBaseImageRegistry,
    BaseImageSpecStorage,
    PlatformProfileStorage,
    MeasurementVariantStorage
} from "./interfaces/registries/IBaseImageRegistry.sol";
import {ISignatureVerifier} from "./interfaces/verifiers/ISignatureVerifier.sol";
import {IKeyResolver} from "./interfaces/registries/IKeyResolver.sol";

/// @title BaseImageRegistry
/// @notice Hierarchical registry for base images, platform profiles, and measurement variants
/// @dev Three-level hierarchy: BaseImage → PlatformProfile → MeasurementVariant
///      BaseImage = OS environment (kernel, bootloader, CVM agent)
///      PlatformProfile = cloud provider + TEE configuration
///      MeasurementVariant = machine-type-specific PCR overrides
contract BaseImageRegistry is IBaseImageRegistry {
    // ============================================================================
    // Errors
    // ============================================================================

    error BaseImageAlreadyExists(bytes32 baseImageId);
    error BaseImageNotFound(bytes32 baseImageId);
    error BaseImageNotActive(bytes32 baseImageId);
    error PlatformProfileNotFound(bytes32 platformProfileId);
    error MeasurementVariantNotFound(bytes32 variantId);
    error ArrayLengthMismatch();
    error InvalidSignature();
    error Unauthorized();

    // ============================================================================
    // Storage
    // ============================================================================

    ISignatureVerifier public immutable signatureVerifier;
    IKeyResolver public immutable keyResolver;

    mapping(bytes32 => BaseImageSpecStorage) private _baseImages;
    mapping(bytes32 => PlatformProfileStorage) private _platformProfiles;
    mapping(bytes32 => MeasurementVariantStorage) private _variants;
    mapping(bytes32 => mapping(bytes32 => bool)) private _baseImageVariants;

    // ============================================================================
    // Constructor
    // ============================================================================

    constructor(ISignatureVerifier _signatureVerifier, IKeyResolver _keyResolver) {
        signatureVerifier = _signatureVerifier;
        keyResolver = _keyResolver;
    }

    // ============================================================================
    // External Functions
    // ============================================================================

    /// @inheritdoc IBaseImageRegistry
    function registerBaseImage(
        BaseImageSpec calldata spec,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 baseImageId) {
        // Validate parallel array invariant
        uint256 platformCount = platformProfiles.length;
        if (platformCount != measurementVariants.length) {
            revert ArrayLengthMismatch();
        }

        // Compute owner fingerprint (pure, no state write)
        bytes32 ownerFingerprint = keyResolver.computeFingerprint(ownerIdentity);

        // Compute base image ID
        baseImageId = keccak256(abi.encode(BASEIMAGE_DOMAIN, ownerFingerprint, spec.name, spec.version));

        // Check for duplicate
        if (_baseImages[baseImageId].exists) {
            revert BaseImageAlreadyExists(baseImageId);
        }

        // Build signed message (6-arg: DOMAIN, chainid, address(this), msg.sender, baseImageId, paramsHash)
        bytes32 paramsHash = sha256(abi.encode(spec, platformProfiles, measurementVariants));
        bytes32 message = sha256(_buildRegistrationMessage(baseImageId, paramsHash));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Store base image
        _baseImages[baseImageId].exists = true;
        _baseImages[baseImageId].isActive = true;
        _baseImages[baseImageId].owner = ownerFingerprint;
        _baseImages[baseImageId].spec = spec;

        // Store platform profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];

            // Compute platform profile ID
            bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name));

            // Store platform profile
            _platformProfiles[platformProfileId].exists = true;
            _platformProfiles[platformProfileId].profile = profile;
            _baseImages[baseImageId].platformProfileIds.push(platformProfileId);

            emit PlatformProfileRegistered(baseImageId, platformProfileId, profile.name);

            // Validate and store measurement variants
            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                MeasurementVariant calldata variant = variants[j];

                // Compute variant ID
                bytes32 variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name));

                // Store variant
                _variants[variantId].exists = true;
                _variants[variantId].variant = variant;
                _platformProfiles[platformProfileId].variantKeys.push(variantId);

                // Link variant to base image
                _baseImageVariants[baseImageId][variantId] = true;

                emit MeasurementVariantRegistered(platformProfileId, variantId, variant.name);
            }
        }

        emit BaseImageRegistered(baseImageId, ownerFingerprint, spec.name, spec.version);
    }

    /// @inheritdoc IBaseImageRegistry
    function deactivateBaseImage(
        bytes32 baseImageId,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check exists and active
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        if (!_baseImages[baseImageId].isActive) {
            revert BaseImageNotActive(baseImageId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = keyResolver.computeFingerprint(ownerIdentity);
        if (_baseImages[baseImageId].owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Build signed message (5-arg: no paramsHash)
        bytes32 message = sha256(_buildDeactivationMessage(baseImageId));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Deactivate
        _baseImages[baseImageId].isActive = false;

        emit BaseImageDeactivated(baseImageId, ownerFingerprint);
    }

    /// @inheritdoc IBaseImageRegistry
    function getBaseImage(bytes32 baseImageId) external view returns (BaseImageSpec memory spec) {
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        return _baseImages[baseImageId].spec;
    }

    /// @inheritdoc IBaseImageRegistry
    function getPlatformProfile(bytes32 platformProfileId)
        external
        view
        returns (PlatformProfile memory platformProfile)
    {
        if (!_platformProfiles[platformProfileId].exists) {
            revert PlatformProfileNotFound(platformProfileId);
        }
        return _platformProfiles[platformProfileId].profile;
    }

    /// @inheritdoc IBaseImageRegistry
    function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory variant) {
        if (!_variants[variantId].exists) {
            revert MeasurementVariantNotFound(variantId);
        }
        return _variants[variantId].variant;
    }

    /// @inheritdoc IBaseImageRegistry
    function getVariant(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        external
        view
        returns (
            BaseImageSpec memory baseImage,
            PlatformProfile memory platformProfile,
            MeasurementVariant memory variant
        )
    {
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        if (!_platformProfiles[platformProfileId].exists) {
            revert PlatformProfileNotFound(platformProfileId);
        }
        if (!_variants[variantId].exists) {
            revert MeasurementVariantNotFound(variantId);
        }

        return
            (_baseImages[baseImageId].spec, _platformProfiles[platformProfileId].profile, _variants[variantId].variant);
    }

    /// @inheritdoc IBaseImageRegistry
    function getBaseImageOwner(bytes32 baseImageId) external view returns (bytes32) {
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        return _baseImages[baseImageId].owner;
    }

    /// @inheritdoc IBaseImageRegistry
    function isBaseImageActive(bytes32 baseImageId) external view returns (bool) {
        return _baseImages[baseImageId].exists && _baseImages[baseImageId].isActive;
    }

    /// @inheritdoc IBaseImageRegistry
    function hasVariant(bytes32 baseImageId, bytes32 variantId) external view returns (bool) {
        return _baseImageVariants[baseImageId][variantId];
    }

    // ============================================================================
    // Internal Helper Functions
    // ============================================================================

    /// @dev Constructs the registration message for signature verification
    /// @param baseImageId The base image identifier
    /// @param paramsHash The hash of registration parameters (spec, profiles, variants)
    /// @return The encoded message ready for hashing
    function _buildRegistrationMessage(bytes32 baseImageId, bytes32 paramsHash) internal view returns (bytes memory) {
        return abi.encode(BASEIMAGE_DOMAIN, block.chainid, address(this), msg.sender, baseImageId, paramsHash);
    }

    /// @dev Constructs the deactivation message for signature verification
    /// @param baseImageId The base image identifier
    /// @return The encoded message ready for hashing
    function _buildDeactivationMessage(bytes32 baseImageId) internal view returns (bytes memory) {
        return abi.encode(BASEIMAGE_DOMAIN, block.chainid, address(this), msg.sender, baseImageId);
    }
}
