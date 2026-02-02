// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {WorkloadSpec, PublicIdentity} from "../../types/Common.sol";

/// @notice Storage wrapper for workload specifications
struct WorkloadSpecStorage {
    /// @dev Existence flag to distinguish unregistered from registered workloads
    bool exists;
    /// @dev The workload specification
    WorkloadSpec workloadSpec;
}

interface IWorkloadRegistry {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a new workload is registered
    /// @param workloadId Computed identifier for the workload
    /// @param owner Owner fingerprint (bytes32 encoding of PublicIdentity fingerprint)
    /// @param name Human-readable workload name
    /// @param version Semantic version string
    event WorkloadRegistered(bytes32 indexed workloadId, bytes32 indexed owner, string name, string version);

    /// @notice Emitted when a workload is deactivated (soft delete)
    /// @param workloadId The workload identifier
    /// @param owner The workload owner fingerprint
    event WorkloadDeactivated(bytes32 indexed workloadId, bytes32 indexed owner);

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a new workload with policy and PCR specifications (immutable after registration)
    /// @dev Workload ID is computed as: keccak256(abi.encode(WORKLOAD_DOMAIN, ownerFingerprint, spec.name, spec.version))
    /// @param spec Complete workload specification (name, version, policy, pcrs)
    /// @param ownerIdentity The public key identity of the workload owner
    /// @param ownerSignature Signature over the workload registration data by ownerIdentity
    /// @return workloadId The unique identifier for the registered workload (domain-separated hash)
    function registerWorkload(
        WorkloadSpec calldata spec,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 workloadId);

    /// @notice Deactivate a workload (soft delete)
    /// @param workloadId The workload identifier
    /// @param ownerIdentity The public key identity of the workload owner
    /// @param ownerSignature Signature over the deactivation request by ownerIdentity
    function deactivateWorkload(
        bytes32 workloadId,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Get complete workload specification
    /// @param workloadId The workload identifier
    /// @return spec The complete workload specification
    function getWorkload(bytes32 workloadId) external view returns (WorkloadSpec memory spec);

    /// @notice Check if a workload is active
    /// @param workloadId The workload identifier
    /// @return True if the workload is active
    function isWorkloadActive(bytes32 workloadId) external view returns (bool);

    /// @notice Check if a base image is allowed for a workload
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @return True if the base image is allowed
    function isBaseImageAllowed(bytes32 workloadId, bytes32 baseImageId) external view returns (bool);
}
