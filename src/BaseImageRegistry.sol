// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    PublicIdentity,
    PcrSpec256,
    PcrSpec384,
    PcrBankSelection,
    Attribute
} from "./types/Common.sol";
import {
    BASEIMAGE_DOMAIN,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    BASEIMAGE_REGISTER_MSG,
    BASEIMAGE_DEACTIVATE_MSG,
    BASEIMAGE_UPDATE_MSG,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
    TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
    TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
    TDX_TCB_STATUS_OK,
    TDX_TCB_STATUS_CONFIGURABLE_MASK,
    TEE_ATTRIBUTE_TRUE
} from "./types/Constants.sol";
import {
    IBaseImageRegistry,
    BaseImageSpecStorage,
    PlatformProfileStorage,
    MeasurementVariantStorage
} from "./interfaces/registries/IBaseImageRegistry.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {LibKey} from "./lib/LibKey.sol";
import {AmdSnpPolicy} from "./lib/AmdSnpPolicy.sol";
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
    /// @notice Thrown by getVariant when the (baseImageId, platformProfileId, variantId)
    ///         triple is not a valid parent-child chain (each id exists in isolation but
    ///         the platform profile / variant was registered under a different parent).
    error HierarchyMismatch(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId);
    /// @dev `registerBaseImage` saw two entries in its `platformProfiles` input with the
    ///      same `name` — without this guard the second would silently overwrite the first's
    ///      metadata and push a duplicate id into `platformProfileIds`. `addPlatformVariants`
    ///      accepts an existing profile only when every submitted profile field equals the
    ///      stored profile.
    error PlatformProfileAlreadyExists(bytes32 profileId);
    error ArrayLengthMismatch(uint256 platformProfilesLen, uint256 measurementVariantsLen);
    error InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint);
    error Unauthorized(bytes32 actualOwner, bytes32 expectedOwner);
    error SignatureExpired(uint64 opExpiresAt, uint64 nowTs);
    /// @notice PCR spec list is not sorted strictly ascending by pcrIndex.
    ///         prevIndex sits at i-1 and thisIndex at i in the input array.
    error InvalidPcrOrder(uint8 prevIndex, uint8 thisIndex);
    error PcrIndexOutOfRange(uint8 pcrIndex);
    error EmptyPcrComparison(uint8 pcrIndex);
    error DuplicateAttributeKey(bytes32 key);
    error InvalidTeeAttributeValue(bytes32 key, bytes32 actualValue);
    /// @notice A measurement variant pins a PCR index that its platform profile already declares
    ///         invariant. Profile invariants always hold; a variant may only pin indices the
    ///         profile leaves unpinned. To make a PCR machine-type dependent, publish a base image
    ///         whose profile does not list it as an invariant.
    error VariantOverridesInvariantPcr(bytes32 platformProfileId, uint8 pcrIndex);
    error NotWhitelisted(bytes32 ownerFingerprint);
    error PlatformProfileMetadataMismatch(bytes32 platformProfileId);

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
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 baseImageId) {
        // Validate parallel array invariant
        uint256 platformCount = platformProfiles.length;
        if (platformCount != measurementVariants.length) {
            revert ArrayLengthMismatch(platformCount, measurementVariants.length);
        }

        // Check signature expiration
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
        }

        // Validate PCR ordering for profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];
            _validatePcrSpecs256Sorted(profile.invariantPcrs256);
            _validatePcrSpecs384Sorted(profile.invariantPcrs384);
            _validateAttributes(profile.attributes);

            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                _validatePcrSpecs256Sorted(variants[j].variantPcrs256);
                _validatePcrSpecs384Sorted(variants[j].variantPcrs384);
                _validateAttributes(variants[j].attributes);
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
                opExpiresAt,
                spec,
                platformProfiles,
                measurementVariants
            )
        );

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature(message, ownerFingerprint);
        }

        // Store base image
        _baseImages[baseImageId].exists = true;
        _baseImages[baseImageId].isRevoked = false;
        _baseImages[baseImageId].owner = ownerFingerprint;
        _baseImages[baseImageId].spec = spec;

        // Store platform profiles and variants. Within this single call, profile.name and
        // variant.name must each be unique per profile — duplicates in the input arrays would
        // otherwise silently overwrite an earlier entry's metadata and push a duplicate id
        // into the parent's `platformProfileIds` / `variantIds` list (corrupt invariant).
        // The exists checks reject those duplicates explicitly; the same guards exist on the
        // `addPlatformVariants` path.
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];

            // Compute platform profile ID
            bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name));

            if (_platformProfiles[platformProfileId].exists) {
                revert PlatformProfileAlreadyExists(platformProfileId);
            }

            // Store platform profile
            _platformProfiles[platformProfileId].exists = true;
            _storePlatformProfile(platformProfileId, profile);
            _baseImages[baseImageId].platformProfileIds.push(platformProfileId);

            emit PlatformProfileRegistered(baseImageId, platformProfileId, profile.name);

            // Validate and store measurement variants
            uint256 invariantMask256 = _pcrIndexMask256(profile.invariantPcrs256);
            uint256 invariantMask384 = _pcrIndexMask384(profile.invariantPcrs384);
            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                MeasurementVariant calldata variant = variants[j];

                _requireNoInvariantOverlap256(platformProfileId, invariantMask256, variant.variantPcrs256);
                _requireNoInvariantOverlap384(platformProfileId, invariantMask384, variant.variantPcrs384);

                // Compute variant ID
                bytes32 variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name));

                if (_variants[variantId].exists) {
                    revert MeasurementVariantAlreadyExists(variantId);
                }

                // Store variant
                _variants[variantId].exists = true;
                _storeMeasurementVariant(variantId, variant);
                _platformProfiles[platformProfileId].variantIds.push(variantId);

                emit MeasurementVariantRegistered(platformProfileId, variantId, variant.name);
            }
        }

        emit BaseImageRegistered(baseImageId, ownerFingerprint, spec.name, spec.version);
    }

    /// @inheritdoc IBaseImageRegistry
    function deactivateBaseImage(
        bytes32 baseImageId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check signature expiration
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
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
            revert Unauthorized(ownerFingerprint, _baseImages[baseImageId].owner);
        }

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message =
            sha256(abi.encode(BASEIMAGE_DEACTIVATE_MSG, block.chainid, address(this), opExpiresAt, baseImageId));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature(message, ownerFingerprint);
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
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Validate parallel array invariant
        uint256 platformCount = platformProfiles.length;
        if (platformCount != measurementVariants.length) {
            revert ArrayLengthMismatch(platformCount, measurementVariants.length);
        }

        // Check signature expiration
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
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
            revert Unauthorized(ownerFingerprint, _baseImages[baseImageId].owner);
        }

        // Appending a variant publishes a new selectable policy branch that may declare its own
        // reserved TEE attributes, so it is gated exactly like a fresh registration. Without this
        // an owner removed from the whitelist could still widen the policy of a base image they
        // registered while whitelisted.
        _checkRegistrationAllowed(ownerFingerprint);

        // Validate PCR ordering and attribute uniqueness for all profiles and variants
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];
            _validatePcrSpecs256Sorted(profile.invariantPcrs256);
            _validatePcrSpecs384Sorted(profile.invariantPcrs384);
            _validateAttributes(profile.attributes);

            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                _validatePcrSpecs256Sorted(variants[j].variantPcrs256);
                _validatePcrSpecs384Sorted(variants[j].variantPcrs384);
                _validateAttributes(variants[j].attributes);
            }
        }

        // Build and verify signature
        bytes32 message = sha256(
            abi.encode(
                BASEIMAGE_UPDATE_MSG,
                block.chainid,
                address(this),
                opExpiresAt,
                baseImageId,
                platformProfiles,
                measurementVariants
            )
        );

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature(message, ownerFingerprint);
        }

        // Append-only: existing profile and variant ids cannot be overwritten.
        // For an existing profile, only its variant set may grow. The submitted
        // bank, PCR rules, and attributes must exactly match the stored profile.
        // New (variantId) values are stored fresh. Any
        // attempt to re-register a variantId that already exists reverts.
        // This prevents post-hoc changes to policies that downstream sessions
        // already reference. A newly appended variant is a new immutable
        // policy branch and may declare its own validated attributes.
        for (uint256 i = 0; i < platformCount; i++) {
            PlatformProfile calldata profile = platformProfiles[i];

            // Compute platform profile ID (deterministic from base image + profile name)
            bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name));

            // An existing profile may append variants only when all profile metadata matches.
            if (!_platformProfiles[platformProfileId].exists) {
                _platformProfiles[platformProfileId].exists = true;
                _storePlatformProfile(platformProfileId, profile);
                _baseImages[baseImageId].platformProfileIds.push(platformProfileId);
                emit PlatformProfileRegistered(baseImageId, platformProfileId, profile.name);
            } else {
                if (!_platformProfileMatches(platformProfileId, profile)) {
                    revert PlatformProfileMetadataMismatch(platformProfileId);
                }
            }

            // Append measurement variants for this profile. Overlap is checked against the
            // stored invariants after exact submitted-metadata validation.
            uint256 invariantMask256 =
                _storedPcrIndexMask256(_platformProfiles[platformProfileId].platformProfile.invariantPcrs256);
            uint256 invariantMask384 =
                _storedPcrIndexMask384(_platformProfiles[platformProfileId].platformProfile.invariantPcrs384);
            MeasurementVariant[] calldata variants = measurementVariants[i];
            for (uint256 j = 0; j < variants.length; j++) {
                MeasurementVariant calldata variant = variants[j];

                _requireNoInvariantOverlap256(platformProfileId, invariantMask256, variant.variantPcrs256);
                _requireNoInvariantOverlap384(platformProfileId, invariantMask384, variant.variantPcrs384);

                // Compute variant ID (deterministic from profile + variant name)
                bytes32 variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name));

                if (_variants[variantId].exists) {
                    revert MeasurementVariantAlreadyExists(variantId);
                }

                _variants[variantId].exists = true;
                _storeMeasurementVariant(variantId, variant);
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
    function getPlatformProfileIds(bytes32 baseImageId) external view returns (bytes32[] memory profileIds) {
        if (!_baseImages[baseImageId].exists) {
            revert BaseImageNotFound(baseImageId);
        }
        return _baseImages[baseImageId].platformProfileIds;
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
        return _loadPlatformProfile(platformProfileId);
    }

    /// @inheritdoc IBaseImageRegistry
    function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory variant) {
        if (!_variants[variantId].exists) {
            revert MeasurementVariantNotFound(variantId);
        }
        return _loadMeasurementVariant(variantId);
    }

    /// @inheritdoc IBaseImageRegistry
    function getMeasurementVariantIds(bytes32 platformProfileId) external view returns (bytes32[] memory variantIds) {
        if (!_platformProfiles[platformProfileId].exists) {
            revert PlatformProfileNotFound(platformProfileId);
        }
        return _platformProfiles[platformProfileId].variantIds;
    }

    /// @inheritdoc IBaseImageRegistry
    /// @dev Hierarchy binding: child IDs are computed deterministically from their parent
    ///      (platformProfileId = keccak256(PLATFORM_PROFILE_DOMAIN, baseImageId, profile.name);
    ///       variantId = keccak256(PLATFORM_VARIANT_DOMAIN, platformProfileId, variant.name)).
    ///      Existence alone is insufficient — without re-deriving and comparing, a caller
    ///      could pass a platformProfileId/variantId that exists but was registered under a
    ///      different baseImageId/platformProfileId, mixing unrelated PCR policy with a
    ///      target base image. SessionRegistry._lookupPolicy depends on this guarantee.
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
        // Recompute child IDs from the provided parent and the stored child name;
        // by collision resistance, a match proves the child was registered under that
        // exact parent. Otherwise reject the triple.
        bytes32 expectedProfileId = keccak256(
            abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, _platformProfiles[platformProfileId].platformProfile.name)
        );
        bytes32 expectedVariantId = keccak256(
            abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, _variants[variantId].measurementVariant.name)
        );
        if (expectedProfileId != platformProfileId || expectedVariantId != variantId) {
            revert HierarchyMismatch(baseImageId, platformProfileId, variantId);
        }

        return
            (_baseImages[baseImageId].spec, _loadPlatformProfile(platformProfileId), _loadMeasurementVariant(variantId));
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

    /// @notice Returns true when only whitelisted owners may register or update base images.
    function registrationRestricted() public view override returns (bool) {
        return paused();
    }

    /// @notice Restricts registration and updates to whitelisted owners.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Restores permissionless registration and updates.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============================================================================
    // Internal Functions
    // ============================================================================

    /// @dev Checks if registration is allowed based on restriction state and whitelist
    /// @param ownerFingerprint The owner's fingerprint
    function _checkRegistrationAllowed(bytes32 ownerFingerprint) private view {
        if (registrationRestricted() && !_whitelist[ownerFingerprint]) {
            revert NotWhitelisted(ownerFingerprint);
        }
    }

    function _validatePcrSpecs256Sorted(PcrSpec256[] calldata pcrs) private pure {
        uint256 len = pcrs.length;
        uint256 prevIdx;
        for (uint256 i = 0; i < len; i++) {
            uint8 idx = pcrs[i].pcrIndex;
            if (idx > 16 && idx != 23) {
                revert PcrIndexOutOfRange(idx);
            }
            if (i > 0 && idx <= prevIdx) {
                revert InvalidPcrOrder(uint8(prevIdx), idx);
            }
            if (pcrs[i].comparison.length == 0) revert EmptyPcrComparison(idx);
            prevIdx = idx;
        }
    }

    function _validatePcrSpecs384Sorted(PcrSpec384[] calldata pcrs) private pure {
        uint256 len = pcrs.length;
        uint256 prevIdx;
        for (uint256 i = 0; i < len; i++) {
            uint8 idx = pcrs[i].pcrIndex;
            if (idx > 16 && idx != 23) {
                revert PcrIndexOutOfRange(idx);
            }
            if (i > 0 && idx <= prevIdx) {
                revert InvalidPcrOrder(uint8(prevIdx), idx);
            }
            if (pcrs[i].comparison.length == 0) revert EmptyPcrComparison(idx);
            prevIdx = idx;
        }
    }

    function _validateAttributes(Attribute[] calldata attrs) private pure {
        uint256 len = attrs.length;
        for (uint256 i = 0; i < len; i++) {
            bytes32 key = attrs[i].key;
            if (_isBooleanTeeAttributeKey(key) && attrs[i].value != bytes32(0) && attrs[i].value != TEE_ATTRIBUTE_TRUE)
            {
                revert InvalidTeeAttributeValue(key, attrs[i].value);
            }
            if (key == TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED) {
                uint256 mask = uint256(attrs[i].value);
                if ((mask & TDX_TCB_STATUS_OK) == 0 || (mask & ~TDX_TCB_STATUS_CONFIGURABLE_MASK) != 0) {
                    revert InvalidTeeAttributeValue(key, attrs[i].value);
                }
            } else if (key == TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM && !AmdSnpPolicy.isValidTcb(attrs[i].value)) {
                revert InvalidTeeAttributeValue(key, attrs[i].value);
            } else if (
                key == TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY
                    && !AmdSnpPolicy.isValidPlatformInfoPolicy(attrs[i].value)
            ) {
                revert InvalidTeeAttributeValue(key, attrs[i].value);
            }
        }
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

    /// @dev Bitmask of the PCR indices a spec list pins. `_validatePcrSpecsSorted` has already
    ///      rejected any index >= 24, so the shift cannot overflow the mask.
    function _pcrIndexMask256(PcrSpec256[] calldata pcrs) private pure returns (uint256 mask) {
        uint256 len = pcrs.length;
        for (uint256 i = 0; i < len; i++) {
            mask |= uint256(1) << pcrs[i].pcrIndex;
        }
    }

    /// @dev Storage-reading counterpart of `_pcrIndexMask`, for an already-registered profile.
    function _pcrIndexMask384(PcrSpec384[] calldata pcrs) private pure returns (uint256 mask) {
        uint256 len = pcrs.length;
        for (uint256 i = 0; i < len; i++) {
            mask |= uint256(1) << pcrs[i].pcrIndex;
        }
    }

    function _storedPcrIndexMask256(PcrSpec256[] storage pcrs) private view returns (uint256 mask) {
        uint256 len = pcrs.length;
        for (uint256 i = 0; i < len; i++) {
            mask |= uint256(1) << pcrs[i].pcrIndex;
        }
    }

    function _storedPcrIndexMask384(PcrSpec384[] storage pcrs) private view returns (uint256 mask) {
        uint256 len = pcrs.length;
        for (uint256 i = 0; i < len; i++) {
            mask |= uint256(1) << pcrs[i].pcrIndex;
        }
    }

    /// @dev Rejects a variant that pins a PCR index its platform profile declares invariant.
    function _requireNoInvariantOverlap256(
        bytes32 platformProfileId,
        uint256 invariantMask,
        PcrSpec256[] calldata variantPcrs
    ) private pure {
        uint256 len = variantPcrs.length;
        for (uint256 i = 0; i < len; i++) {
            uint8 pcrIndex = variantPcrs[i].pcrIndex;
            if ((invariantMask & (uint256(1) << pcrIndex)) != 0) {
                revert VariantOverridesInvariantPcr(platformProfileId, pcrIndex);
            }
        }
    }

    function _requireNoInvariantOverlap384(
        bytes32 platformProfileId,
        uint256 invariantMask,
        PcrSpec384[] calldata variantPcrs
    ) private pure {
        uint256 len = variantPcrs.length;
        for (uint256 i = 0; i < len; i++) {
            uint8 pcrIndex = variantPcrs[i].pcrIndex;
            if ((invariantMask & (uint256(1) << pcrIndex)) != 0) {
                revert VariantOverridesInvariantPcr(platformProfileId, pcrIndex);
            }
        }
    }

    function _storePlatformProfile(bytes32 platformProfileId, PlatformProfile calldata profile) private {
        PlatformProfileStorage storage stored = _platformProfiles[platformProfileId];
        stored.platformProfile = profile;
    }

    function _storeMeasurementVariant(bytes32 variantId, MeasurementVariant calldata variant) private {
        MeasurementVariantStorage storage stored = _variants[variantId];
        stored.measurementVariant = variant;
    }

    function _loadPlatformProfile(bytes32 platformProfileId) private view returns (PlatformProfile memory profile) {
        profile = _platformProfiles[platformProfileId].platformProfile;
    }

    function _loadMeasurementVariant(bytes32 variantId) private view returns (MeasurementVariant memory variant) {
        variant = _variants[variantId].measurementVariant;
    }

    function _platformProfileMatches(bytes32 platformProfileId, PlatformProfile calldata supplied)
        private
        view
        returns (bool)
    {
        PlatformProfile memory stored = _loadPlatformProfile(platformProfileId);
        return keccak256(bytes(stored.name)) == keccak256(bytes(supplied.name))
            && stored.pcrBankSelection == supplied.pcrBankSelection
            && keccak256(abi.encode(stored.invariantPcrs256)) == keccak256(abi.encode(supplied.invariantPcrs256))
            && keccak256(abi.encode(stored.invariantPcrs384)) == keccak256(abi.encode(supplied.invariantPcrs384))
            && keccak256(abi.encode(stored.attributes)) == keccak256(abi.encode(supplied.attributes));
    }

    function _isBooleanTeeAttributeKey(bytes32 key) private pure returns (bool) {
        return key == TEE_ATTRIBUTE_INTEL_TDX_DEBUG || key == TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            || key == TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA;
    }

    // ============================================================================
    // Internal Functions - UUPS
    // ============================================================================

    /// @dev Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
