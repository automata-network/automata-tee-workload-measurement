// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    PublicIdentity,
    PcrSpec,
    PcrVerifyType,
    Attribute
} from "./types/Common.sol";
import {
    BASEIMAGE_DOMAIN,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    BASEIMAGE_REGISTER_MSG,
    BASEIMAGE_DEACTIVATE_MSG,
    BASEIMAGE_UPDATE_MSG
} from "./types/Constants.sol";
import {
    IBaseImageRegistry,
    BaseImageSpecStorage,
    PlatformProfileStorage,
    MeasurementVariantStorage
} from "./interfaces/registries/IBaseImageRegistry.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {LibKey} from "./lib/LibKey.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title BaseImageRegistry
/// @notice Hierarchical registry for base images, platform profiles, and measurement variants
/// @dev Three-level hierarchy: BaseImage → PlatformProfile → MeasurementVariant
///      BaseImage = OS environment (kernel, bootloader, CVM agent)
///      PlatformProfile = cloud provider + TEE configuration
///      MeasurementVariant = machine-type-specific PCR overrides
contract BaseImageRegistry is IBaseImageRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    // ============================================================================
    // Errors
    // ============================================================================

    error BaseImageAlreadyExists(bytes32 baseImageId);
    error BaseImageNotFound(bytes32 baseImageId);
    error BaseImageNotActive(bytes32 baseImageId);
    error PlatformProfileNotFound(bytes32 platformProfileId);
    error MeasurementVariantNotFound(bytes32 variantId);
    error MeasurementVariantAlreadyExists(bytes32 variantId);
    /// @dev addPlatformVariants got an existing profile id with non-empty `invariants` or
    ///      `attributes`. Existing profile metadata is immutable post-registration; to grow
    ///      the variant set of an existing profile, submit a PlatformProfile whose only
    ///      non-empty field is `name`. See §14.2.
    error PlatformProfileAlreadyExists(bytes32 profileId);
    error ArrayLengthMismatch();
    error InvalidSignature();
    error Unauthorized();
    error SignatureExpired();
    error InvalidPcrOrder();
    error PcrIndexOutOfRange(uint8 pcrIndex);
    error EmptyMatchData(uint8 pcrIndex);
    error DuplicateAttributeKey(bytes32 key);
    error NotWhitelisted(bytes32 ownerFingerprint);

    // ============================================================================
    // Events
    // ============================================================================

    event WhitelistAdded(bytes32 indexed fingerprint);
    event WhitelistRemoved(bytes32 indexed fingerprint);

    // ============================================================================
    // Storage
    // ============================================================================

    ISignatureVerifier public immutable signatureVerifier;

    mapping(bytes32 => BaseImageSpecStorage) private _baseImages;
    mapping(bytes32 => PlatformProfileStorage) private _platformProfiles;
    mapping(bytes32 => MeasurementVariantStorage) private _variants;
    mapping(bytes32 => bool) private _whitelist;

    /// @dev Storage gap for future upgrades (4 existing mappings → 46-slot gap)
    uint256[46] private __gap;

    // ============================================================================
    // Constructor & Initialization
    // ============================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(ISignatureVerifier _signatureVerifier) {
        signatureVerifier = _signatureVerifier;
        _disableInitializers();
    }

    /// @notice Initializes the contract with the initial owner and paused state
    /// @param initialOwner The address that will own the contract
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        __Pausable_init();
        _pause();
    }

    // ============================================================================
    // External Functions
    // ============================================================================

    /// @inheritdoc IBaseImageRegistry
    function registerBaseImage(
        BaseImageSpec calldata spec,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 baseImageId) {
        // Validate parallel array invariant
        uint256 platformCount = platformProfiles.length;
        if (platformCount != measurementVariants.length) {
            revert ArrayLengthMismatch();
        }

        // Check signature expiration
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // Validate PCR ordering for profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];
            _validatePcrSpecsSorted(profile.invariants);
            _validateUniqueAttributeKeys(profile.attributes);

            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                _validatePcrSpecsSorted(variants[j].overridePcrs);
                _validateUniqueAttributeKeys(variants[j].attributes);
            }
        }

        // Compute base image ID
        baseImageId = keccak256(abi.encode(BASEIMAGE_DOMAIN, spec.name, spec.version));

        // Check for duplicate
        if (_baseImages[baseImageId].exists) {
            revert BaseImageAlreadyExists(baseImageId);
        }

        // Compute owner fingerprint after duplicate check
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);

        // Check whitelist if paused
        _checkRegistrationAllowed(ownerFingerprint);

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message = sha256(
            abi.encode(
                BASEIMAGE_REGISTER_MSG,
                block.chainid,
                address(this),
                expireAt,
                spec,
                platformProfiles,
                measurementVariants
            )
        );

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Store base image
        _baseImages[baseImageId].exists = true;
        _baseImages[baseImageId].isRevoked = false;
        _baseImages[baseImageId].owner = ownerFingerprint;
        _baseImages[baseImageId].spec = spec;

        // Store platform profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];

            // Compute platform profile ID
            bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name));

            // Store platform profile
            _platformProfiles[platformProfileId].exists = true;
            _platformProfiles[platformProfileId].platformProfile = profile;
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
                _variants[variantId].measurementVariant = variant;
                _platformProfiles[platformProfileId].variantIds.push(variantId);

                emit MeasurementVariantRegistered(platformProfileId, variantId, variant.name);
            }
        }

        emit BaseImageRegistered(baseImageId, ownerFingerprint, spec.name, spec.version);
    }

    /// @inheritdoc IBaseImageRegistry
    function deactivateBaseImage(
        bytes32 baseImageId,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check signature expiration
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // Check exists and active
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        if (_baseImages[baseImageId].isRevoked) {
            revert BaseImageNotActive(baseImageId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (_baseImages[baseImageId].owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message =
            sha256(abi.encode(BASEIMAGE_DEACTIVATE_MSG, block.chainid, address(this), expireAt, baseImageId));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Deactivate
        _baseImages[baseImageId].isRevoked = true;

        emit BaseImageDeactivated(baseImageId, ownerFingerprint);
    }

    /// @inheritdoc IBaseImageRegistry
    function addPlatformVariants(
        bytes32 baseImageId,
        PlatformProfile[] calldata platformProfiles,
        MeasurementVariant[][] calldata measurementVariants,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Validate parallel array invariant
        uint256 platformCount = platformProfiles.length;
        if (platformCount != measurementVariants.length) {
            revert ArrayLengthMismatch();
        }

        // Check signature expiration
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // Check exists and active
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        if (_baseImages[baseImageId].isRevoked) {
            revert BaseImageNotActive(baseImageId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (_baseImages[baseImageId].owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Validate PCR ordering and attribute uniqueness for all profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];
            _validatePcrSpecsSorted(profile.invariants);
            _validateUniqueAttributeKeys(profile.attributes);

            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                _validatePcrSpecsSorted(variants[j].overridePcrs);
                _validateUniqueAttributeKeys(variants[j].attributes);
            }
        }

        // Build and verify signature
        bytes32 message = sha256(
            abi.encode(
                BASEIMAGE_UPDATE_MSG,
                block.chainid,
                address(this),
                expireAt,
                baseImageId,
                platformProfiles,
                measurementVariants
            )
        );

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Append-only: existing profile and variant ids cannot be overwritten.
        // New profile ids are registered fresh with their metadata; existing profile ids
        // accept new variants ONLY if the caller submits an otherwise-empty PlatformProfile
        // (invariants.length == 0 && attributes.length == 0), reverting otherwise. This
        // is stricter than the prior silent-drop behavior: it forces the operator's signed
        // authorization to unambiguously match the on-chain effect — non-empty metadata on
        // an existing profile is rejected up-front rather than discarded silently. Any
        // attempt to re-register a variantId that already exists reverts the same way.
        // To publish a different policy, owners must mint a fresh base image with a bumped
        // name or version. See on-chain-registry-design.md §14.2.
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];

            // Compute platform profile ID (deterministic from base image + profile name)
            bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name));

            if (!_platformProfiles[platformProfileId].exists) {
                // New profile: store metadata and link into the base image.
                _platformProfiles[platformProfileId].exists = true;
                _platformProfiles[platformProfileId].platformProfile = profile;
                _baseImages[baseImageId].platformProfileIds.push(platformProfileId);
                emit PlatformProfileRegistered(baseImageId, platformProfileId, profile.name);
            } else if (profile.invariants.length != 0 || profile.attributes.length != 0) {
                // Existing profile: caller MUST submit empty metadata. Any non-empty field
                // here is rejected to avoid the "signed message lies about effect" footgun.
                revert PlatformProfileAlreadyExists(platformProfileId);
            }

            // Append measurement variants for this profile
            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                MeasurementVariant calldata variant = variants[j];

                // Compute variant ID (deterministic from profile + variant name)
                bytes32 variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name));

                if (_variants[variantId].exists) {
                    revert MeasurementVariantAlreadyExists(variantId);
                }

                _variants[variantId].exists = true;
                _variants[variantId].measurementVariant = variant;
                _platformProfiles[platformProfileId].variantIds.push(variantId);

                emit MeasurementVariantRegistered(platformProfileId, variantId, variant.name);
            }
        }

        emit BaseImageUpdated(baseImageId, ownerFingerprint);
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
        return _platformProfiles[platformProfileId].platformProfile;
    }

    /// @inheritdoc IBaseImageRegistry
    function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory variant) {
        if (!_variants[variantId].exists) {
            revert MeasurementVariantNotFound(variantId);
        }
        return _variants[variantId].measurementVariant;
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

        return (
            _baseImages[baseImageId].spec,
            _platformProfiles[platformProfileId].platformProfile,
            _variants[variantId].measurementVariant
        );
    }

    /// @inheritdoc IBaseImageRegistry
    function getBaseImageOwner(bytes32 baseImageId) external view returns (bytes32) {
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        return _baseImages[baseImageId].owner;
    }

    /// @inheritdoc IBaseImageRegistry
    function isBaseImageRevoked(bytes32 baseImageId) external view returns (bool) {
        return _baseImages[baseImageId].isRevoked;
    }

    /// @inheritdoc IBaseImageRegistry
    function hasVariant(bytes32 variantId) external view returns (bool) {
        return _variants[variantId].exists;
    }

    // ============================================================================
    // Admin Functions
    // ============================================================================

    /// @notice Adds fingerprints to the whitelist
    /// @param fingerprints Array of fingerprints to add
    function addToWhitelist(bytes32[] calldata fingerprints) external onlyOwner {
        for (uint256 i = 0; i < fingerprints.length; i++) {
            _whitelist[fingerprints[i]] = true;
            emit WhitelistAdded(fingerprints[i]);
        }
    }

    /// @notice Removes a fingerprint from the whitelist
    /// @param fingerprint The fingerprint to remove
    function removeFromWhitelist(bytes32 fingerprint) external onlyOwner {
        _whitelist[fingerprint] = false;
        emit WhitelistRemoved(fingerprint);
    }

    /// @notice Checks if a fingerprint is whitelisted
    /// @param fingerprint The fingerprint to check
    /// @return True if whitelisted
    function isWhitelisted(bytes32 fingerprint) external view returns (bool) {
        return _whitelist[fingerprint];
    }

    /// @notice Pauses the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============================================================================
    // Internal Functions
    // ============================================================================

    /// @dev Checks if registration is allowed based on pause state and whitelist
    /// @param ownerFingerprint The owner's fingerprint
    function _checkRegistrationAllowed(bytes32 ownerFingerprint) private view {
        if (paused() && !_whitelist[ownerFingerprint]) {
            revert NotWhitelisted(ownerFingerprint);
        }
    }

    function _validatePcrSpecsSorted(PcrSpec[] calldata pcrs) private pure {
        uint256 len = pcrs.length;
        uint256 prevIdx;
        for (uint256 i = 0; i < len; i++) {
            uint8 idx = pcrs[i].pcrIndex;
            if (idx >= 24) {
                revert PcrIndexOutOfRange(idx);
            }
            if (i > 0 && idx <= prevIdx) {
                revert InvalidPcrOrder();
            }
            // DYNAMIC variants with empty matchData would accept any reported
            // event log (subset of nothing is always nothing) or trivially
            // satisfy the subsequence condition — neither is a meaningful
            // policy. STATIC is allowed to have any matchData length here
            // (the session-evaluator reads matchData[0]), since a zero-length
            // STATIC array reverts at session time with an array-bounds panic.
            PcrVerifyType vt = pcrs[i].verifyType;
            if (
                (vt == PcrVerifyType.DYNAMIC_SUBSET || vt == PcrVerifyType.DYNAMIC_SUBSEQUENCE)
                    && pcrs[i].matchData.length == 0
            ) {
                revert EmptyMatchData(idx);
            }
            prevIdx = idx;
        }
    }

    function _validateUniqueAttributeKeys(Attribute[] calldata attrs) private pure {
        uint256 len = attrs.length;
        if (len < 2) {
            return;
        }

        uint256 cap = 1;
        while (cap < len * 2) {
            cap <<= 1;
        }

        bytes32[] memory keys = new bytes32[](cap);
        bool[] memory used = new bool[](cap);

        for (uint256 i = 0; i < len; i++) {
            bytes32 key = attrs[i].key;
            uint256 slot = uint256(key) & (cap - 1);
            while (used[slot]) {
                if (keys[slot] == key) {
                    revert DuplicateAttributeKey(key);
                }
                slot = (slot + 1) & (cap - 1);
            }
            used[slot] = true;
            keys[slot] = key;
        }
    }

    // ============================================================================
    // Internal Functions - UUPS
    // ============================================================================

    /// @dev Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
