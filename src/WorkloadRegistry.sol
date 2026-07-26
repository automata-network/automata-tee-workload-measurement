// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    WorkloadSpec,
    PublicIdentity,
    AccessMode,
    PcrSpec,
    PcrVerifyType,
    AttributeRequirement
} from "./types/Common.sol";
import {
    WORKLOAD_DOMAIN,
    WORKLOAD_REGISTER_MSG,
    WORKLOAD_DEACTIVATE_MSG,
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
import {IWorkloadRegistry, WorkloadSpecStorage} from "./interfaces/registries/IWorkloadRegistry.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {LibKey} from "./lib/LibKey.sol";
import {AmdSnpPolicy} from "./lib/AmdSnpPolicy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title WorkloadRegistry
/// @notice Registry for workload specifications with access control and PCR policies
/// @dev Workload = containerized application (unprivileged), measured by PCR 20-23
///      Supports three access modes: ANY (all base images), WHITELIST (allowed set), BLACKLIST (blocked set)
contract WorkloadRegistry is IWorkloadRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable {
    // ============================================================================
    // Errors
    // ============================================================================

    error WorkloadAlreadyExists(bytes32 workloadId);
    error WorkloadNotFound(bytes32 workloadId);
    error WorkloadNotActive(bytes32 workloadId);
    error InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint);
    error Unauthorized(bytes32 actualOwner, bytes32 expectedOwner);
    error SignatureExpired(uint64 opExpiresAt, uint64 nowTs);
    /// @notice PCR spec list is not sorted strictly ascending by pcrIndex.
    ///         prevIndex sits at i-1 and thisIndex at i in the input array.
    error InvalidPcrOrder(uint8 prevIndex, uint8 thisIndex);
    error PcrIndexOutOfRange(uint8 pcrIndex);
    error EmptyMatchData(uint8 pcrIndex);
    error DuplicateRequirementKey(bytes32 key);
    error InvalidTeeAttributeRequirementLength(bytes32 key, uint256 actualLength);
    error InvalidTeeAttributeRequirementValue(bytes32 key, bytes32 actualValue);
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

    mapping(bytes32 => WorkloadSpecStorage) private _workloads;
    mapping(bytes32 => mapping(bytes32 => bool)) private _baseImageSet;
    mapping(bytes32 => bool) private _whitelist;
    /// @dev Storage gap for future upgrades (3 existing mappings → 47-slot gap)
    uint256[47] private __gap;

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

    /// @inheritdoc IWorkloadRegistry
    function registerWorkload(
        WorkloadSpec calldata spec,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 workloadId) {
        // Check signature expiration
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
        }

        _validatePcrSpecsSorted(spec.pcrs);
        _validateRequirements(spec.requirements);

        // Compute workload ID
        workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, spec.name, spec.version));

        // Check for duplicate
        if (_workloads[workloadId].exists) {
            revert WorkloadAlreadyExists(workloadId);
        }

        // Compute owner fingerprint after duplicate check
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);

        // Check whitelist if paused
        _checkRegistrationAllowed(ownerFingerprint);

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message = sha256(abi.encode(WORKLOAD_REGISTER_MSG, block.chainid, address(this), opExpiresAt, spec));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature(message, ownerFingerprint);
        }

        // Store workload
        _workloads[workloadId].exists = true;
        _workloads[workloadId].isRevoked = false;
        _workloads[workloadId].owner = ownerFingerprint;
        _workloads[workloadId].workloadSpec = spec;

        // Populate base image set
        for (uint256 i = 0; i < spec.baseImageIds.length; i++) {
            _baseImageSet[workloadId][spec.baseImageIds[i]] = true;
        }

        emit WorkloadRegistered(workloadId, ownerFingerprint, spec.name, spec.version);
    }

    /// @inheritdoc IWorkloadRegistry
    function deactivateWorkload(
        bytes32 workloadId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check signature expiration
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
        }

        // Check exists and active
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }
        if (_workloads[workloadId].isRevoked) {
            revert WorkloadNotActive(workloadId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (_workloads[workloadId].owner != ownerFingerprint) {
            revert Unauthorized(ownerFingerprint, _workloads[workloadId].owner);
        }

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message =
            sha256(abi.encode(WORKLOAD_DEACTIVATE_MSG, block.chainid, address(this), opExpiresAt, workloadId));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature(message, ownerFingerprint);
        }

        // Deactivate
        _workloads[workloadId].isRevoked = true;

        emit WorkloadDeactivated(workloadId, ownerFingerprint);
    }

    /// @inheritdoc IWorkloadRegistry
    function getWorkload(bytes32 workloadId) external view returns (WorkloadSpec memory spec) {
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }
        return _workloads[workloadId].workloadSpec;
    }

    /// @inheritdoc IWorkloadRegistry
    function getWorkloadOwner(bytes32 workloadId) external view returns (bytes32) {
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }
        return _workloads[workloadId].owner;
    }

    /// @inheritdoc IWorkloadRegistry
    function isWorkloadRevoked(bytes32 workloadId) external view returns (bool) {
        return _workloads[workloadId].isRevoked;
    }

    /// @inheritdoc IWorkloadRegistry
    function isBaseImageAllowed(bytes32 workloadId, bytes32 baseImageId) external view returns (bool) {
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }

        AccessMode mode = _workloads[workloadId].workloadSpec.baseImageMode;

        if (mode == AccessMode.ANY) {
            return true;
        } else if (mode == AccessMode.WHITELIST) {
            return _baseImageSet[workloadId][baseImageId];
        } else {
            // BLACKLIST
            return !_baseImageSet[workloadId][baseImageId];
        }
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
                revert InvalidPcrOrder(uint8(prevIdx), idx);
            }
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

    function _validateRequirements(AttributeRequirement[] calldata requirements) private pure {
        uint256 len = requirements.length;
        for (uint256 i = 0; i < len; i++) {
            bytes32 key = requirements[i].key;
            if (key == TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED) {
                bytes32[] calldata allowedValues = requirements[i].allowedValues;
                if (allowedValues.length != 1) {
                    revert InvalidTeeAttributeRequirementLength(key, allowedValues.length);
                }
                uint256 mask = uint256(allowedValues[0]);
                if ((mask & TDX_TCB_STATUS_OK) == 0 || (mask & ~TDX_TCB_STATUS_CONFIGURABLE_MASK) != 0) {
                    revert InvalidTeeAttributeRequirementValue(key, allowedValues[0]);
                }
            } else if (
                key == TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM || key == TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY
            ) {
                bytes32[] calldata allowedValues = requirements[i].allowedValues;
                if (allowedValues.length != 1) {
                    revert InvalidTeeAttributeRequirementLength(key, allowedValues.length);
                }
                if (
                    (key == TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM && !AmdSnpPolicy.isValidTcb(allowedValues[0]))
                        || (key == TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY
                            && !AmdSnpPolicy.isValidPlatformInfoPolicy(allowedValues[0]))
                ) {
                    revert InvalidTeeAttributeRequirementValue(key, allowedValues[0]);
                }
            } else if (
                key == TEE_ATTRIBUTE_INTEL_TDX_DEBUG || key == TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
                    || key == TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA
            ) {
                bytes32[] calldata allowedValues = requirements[i].allowedValues;
                uint256 allowedLen = allowedValues.length;
                if (allowedLen != 1 && allowedLen != 2) {
                    revert InvalidTeeAttributeRequirementLength(key, allowedLen);
                }
                if (allowedValues[0] != bytes32(0)) {
                    revert InvalidTeeAttributeRequirementValue(key, allowedValues[0]);
                }
                if (allowedLen == 2 && allowedValues[1] != TEE_ATTRIBUTE_TRUE) {
                    revert InvalidTeeAttributeRequirementValue(key, allowedValues[1]);
                }
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
            bytes32 key = requirements[i].key;
            uint256 slot = uint256(key) & (cap - 1);
            while (used[slot]) {
                if (keys[slot] == key) {
                    revert DuplicateRequirementKey(key);
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
