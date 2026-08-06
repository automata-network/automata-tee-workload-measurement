// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {AttributeRequirement, PcrPolicyBlockMetadata, PublicIdentity, WorkloadSpec} from "../../types/Common.sol";

/// @notice Storage wrapper for workload specifications
struct WorkloadSpecStorage {
    /// @dev Existence flag to distinguish unregistered from registered workloads
    bool exists;
    /// @dev Revoked status flag (soft delete)
    bool isRevoked;
    /// @dev Workload owner fingerprint
    bytes32 owner;
    /// @dev The workload specification
    WorkloadSpec workloadSpec;
    /// @dev Registration-time commitment and PCR-selection bitmaps for workloadPcrPolicy.
    PcrPolicyBlockMetadata workloadPcrPolicyMetadata;
}

interface IWorkloadRegistry {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a new workload is registered
    /// @param workloadId Computed identifier for the workload
    /// @param owner Owner fingerprint
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
    /// @dev Workload ID is computed as:
    ///      keccak256(abi.encode(WORKLOAD_DOMAIN, spec.name, spec.version))
    /// @param spec Complete workload specification (name, version, policy, pcrs)
    /// @param opExpiresAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the workload owner
    /// @param ownerSignature Signature over the workload registration data by ownerIdentity
    /// @return workloadId The unique identifier for the registered workload (domain-separated hash)
    function registerWorkload(
        WorkloadSpec calldata spec,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 workloadId);

    /// @notice Deactivate a workload (soft delete)
    /// @param workloadId The workload identifier
    /// @param opExpiresAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the workload owner
    /// @param ownerSignature Signature over the deactivation request by ownerIdentity
    function deactivateWorkload(
        bytes32 workloadId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Get complete workload specification
    /// @param workloadId The workload identifier
    /// @return spec The complete workload specification
    function getWorkload(bytes32 workloadId) external view returns (WorkloadSpec memory spec);

    /// @notice Get the lightweight workload policy data needed by SessionRegistry.
    /// @dev This function does not return the stored PCR comparison blobs.
    function getWorkloadPolicyMetadata(bytes32 workloadId)
        external
        view
        returns (
            uint64 sessionTtl,
            AttributeRequirement[] memory requirements,
            PcrPolicyBlockMetadata memory workloadPcrPolicyMetadata
        );

    /// @notice Get the owner fingerprint of a registered workload
    /// @dev Returns the keccak256 fingerprint computed from the owner's PublicIdentity
    ///      This fingerprint is used for ownership verification in deactivation and access control
    /// @param workloadId The workload identifier
    /// @return The owner's identity fingerprint (bytes32)
    function getWorkloadOwner(bytes32 workloadId) external view returns (bytes32);

    /// @notice Check if a workload is revoked
    /// @param workloadId The workload identifier
    /// @return True if the workload is revoked
    function isWorkloadRevoked(bytes32 workloadId) external view returns (bool);

    /// @notice Returns true when only whitelisted owners may register workloads.
    function registrationRestricted() external view returns (bool);

    /// @notice Check if a base image is allowed for a workload
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @return True if the base image is allowed
    function isBaseImageAllowed(bytes32 workloadId, bytes32 baseImageId) external view returns (bool);
}
