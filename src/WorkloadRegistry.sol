// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {WorkloadSpec, PublicIdentity, AccessMode, PcrSpec, AttributeRequirement} from "./types/Common.sol";
import {WORKLOAD_DOMAIN, WORKLOAD_REGISTER_MSG, WORKLOAD_DEACTIVATE_MSG} from "./types/Constants.sol";
import {IWorkloadRegistry, WorkloadSpecStorage} from "./interfaces/registries/IWorkloadRegistry.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {LibKey} from "./lib/LibKey.sol";

/// @title WorkloadRegistry
/// @notice Registry for workload specifications with access control and PCR policies
/// @dev Workload = containerized application (unprivileged), measured by PCR 20-23
///      Supports three access modes: ANY (all base images), WHITELIST (allowed set), BLACKLIST (blocked set)
contract WorkloadRegistry is IWorkloadRegistry {
    // ============================================================================
    // Errors
    // ============================================================================

    error WorkloadAlreadyExists(bytes32 workloadId);
    error WorkloadNotFound(bytes32 workloadId);
    error WorkloadNotActive(bytes32 workloadId);
    error InvalidSignature();
    error Unauthorized();
    error SignatureExpired();
    error InvalidPcrOrder();
    error PcrIndexOutOfRange(uint8 pcrIndex);
    error DuplicateRequirementKey(bytes32 key);

    // ============================================================================
    // Storage
    // ============================================================================

    ISignatureVerifier public immutable signatureVerifier;

    mapping(bytes32 => WorkloadSpecStorage) private _workloads;
    mapping(bytes32 => mapping(bytes32 => bool)) private _baseImageSet;

    // ============================================================================
    // Constructor
    // ============================================================================

    constructor(ISignatureVerifier _signatureVerifier) {
        signatureVerifier = _signatureVerifier;
    }

    // ============================================================================
    // External Functions
    // ============================================================================

    /// @inheritdoc IWorkloadRegistry
    function registerWorkload(
        WorkloadSpec calldata spec,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 workloadId) {
        // Check signature expiration
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        _validatePcrSpecsSorted(spec.pcrs);
        _validateUniqueRequirementKeys(spec.requirements);

        // Compute workload ID (simplified: name only)
        workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, spec.name));

        // Check for duplicate
        if (_workloads[workloadId].exists) {
            revert WorkloadAlreadyExists(workloadId);
        }

        // Compute owner fingerprint after duplicate check
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message = sha256(abi.encode(WORKLOAD_REGISTER_MSG, block.chainid, address(this), expireAt, spec));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Store workload
        _workloads[workloadId].exists = true;
        _workloads[workloadId].isActive = true;
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
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check signature expiration
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // Check exists and active
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }
        if (!_workloads[workloadId].isActive) {
            revert WorkloadNotActive(workloadId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (_workloads[workloadId].owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Build signed message (operation-specific domain, no msg.sender, raw params)
        bytes32 message =
            sha256(abi.encode(WORKLOAD_DEACTIVATE_MSG, block.chainid, address(this), expireAt, workloadId));

        // Verify signature
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Deactivate
        _workloads[workloadId].isActive = false;

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
    function isWorkloadActive(bytes32 workloadId) external view returns (bool) {
        return _workloads[workloadId].exists && _workloads[workloadId].isActive;
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
            prevIdx = idx;
        }
    }

    function _validateUniqueRequirementKeys(AttributeRequirement[] calldata requirements) private pure {
        uint256 len = requirements.length;
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
}
