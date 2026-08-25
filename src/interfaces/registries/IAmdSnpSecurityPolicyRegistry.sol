// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

struct AmdSnpSecurityPolicy {
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    bytes32 sourceDigest;
    uint64 revision;
    bool active;
    /// @dev Required bits in a version-5 report's LAUNCH_MIT_VECTOR.
    uint64 requiredLaunchMitigationVector;
    /// @dev Required bits in a version-5 report's CURRENT_MIT_VECTOR.
    uint64 requiredCurrentMitigationVector;
}

struct AmdSnpSecurityPolicyUpdate {
    uint24 cpuid;
    /// @dev Revision that must currently be stored. Use zero when creating a policy.
    uint64 expectedRevision;
    uint64 revision;
    bool active;
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    uint64 requiredLaunchMitigationVector;
    uint64 requiredCurrentMitigationVector;
}

interface IAmdSnpSecurityPolicyRegistry {
    event AmdSnpSecurityPolicyUpdated(
        uint24 indexed cpuid,
        uint64 revision,
        bool active,
        bytes32 minimumTcb,
        bytes32 platformInfoPolicy,
        uint64 requiredLaunchMitigationVector,
        uint64 requiredCurrentMitigationVector,
        bytes32 sourceDigest
    );

    function updatePolicies(AmdSnpSecurityPolicyUpdate[] calldata updates, bytes32 sourceDigest) external;

    function getPolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy);

    function getActivePolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy);
}
