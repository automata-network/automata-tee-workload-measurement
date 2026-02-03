// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {WorkloadSpec, PublicIdentity, AccessMode} from "./types/Common.sol";
import {WORKLOAD_DOMAIN} from "./types/Constants.sol";
import {IWorkloadRegistry, WorkloadSpecStorage} from "./interfaces/registries/IWorkloadRegistry.sol";
import {ISignatureVerifier} from "./interfaces/verifiers/ISignatureVerifier.sol";
import {IKeyResolver} from "./interfaces/registries/IKeyResolver.sol";

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

    // ============================================================================
    // Storage
    // ============================================================================

    ISignatureVerifier public immutable signatureVerifier;
    IKeyResolver public immutable keyResolver;

    mapping(bytes32 => WorkloadSpecStorage) private _workloads;
    mapping(bytes32 => mapping(bytes32 => bool)) private _baseImageSet;

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

    /// @inheritdoc IWorkloadRegistry
    function registerWorkload(
        WorkloadSpec calldata spec,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 workloadId) {
        // Compute owner fingerprint (pure, no state write)
        bytes32 ownerFingerprint = keyResolver.computeFingerprint(ownerIdentity);

        // Compute workload ID
        workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, ownerFingerprint, spec.name, spec.version));

        // Check for duplicate
        if (_workloads[workloadId].exists) {
            revert WorkloadAlreadyExists(workloadId);
        }

        // Build signed message (6-arg)
        bytes32 paramsHash = sha256(abi.encode(spec));
        bytes32 message = sha256(_buildRegistrationMessage(workloadId, paramsHash));

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
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check exists and active
        if (!_workloads[workloadId].exists) {
            revert WorkloadNotFound(workloadId);
        }
        if (!_workloads[workloadId].isActive) {
            revert WorkloadNotActive(workloadId);
        }

        // Compute owner fingerprint and verify ownership
        bytes32 ownerFingerprint = keyResolver.computeFingerprint(ownerIdentity);
        if (_workloads[workloadId].owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Build signed message (5-arg: no paramsHash)
        bytes32 message = sha256(_buildDeactivationMessage(workloadId));

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

    // ============================================================================
    // Internal Helper Functions
    // ============================================================================

    /// @dev Constructs the registration message for signature verification
    /// @param workloadId The workload identifier
    /// @param paramsHash The hash of registration parameters (spec)
    /// @return The encoded message ready for hashing
    function _buildRegistrationMessage(bytes32 workloadId, bytes32 paramsHash) internal view returns (bytes memory) {
        return abi.encode(WORKLOAD_DOMAIN, block.chainid, address(this), msg.sender, workloadId, paramsHash);
    }

    /// @dev Constructs the deactivation message for signature verification
    /// @param workloadId The workload identifier
    /// @return The encoded message ready for hashing
    function _buildDeactivationMessage(bytes32 workloadId) internal view returns (bytes memory) {
        return abi.encode(WORKLOAD_DOMAIN, block.chainid, address(this), msg.sender, workloadId);
    }
}
