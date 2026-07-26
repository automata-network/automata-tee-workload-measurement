// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

struct AmdSnpSecurityPolicy {
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    bytes32 sourceDigest;
    uint64 revision;
    bool active;
}

struct AmdSnpSecurityPolicyUpdate {
    uint24 cpuid;
    uint64 revision;
    bool active;
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
}

interface IAmdSnpSecurityPolicyRegistry {
    event AmdSnpSecurityPolicyUpdated(
        uint24 indexed cpuid,
        uint64 revision,
        bool active,
        bytes32 minimumTcb,
        bytes32 platformInfoPolicy,
        bytes32 sourceDigest
    );

    function updatePolicies(AmdSnpSecurityPolicyUpdate[] calldata updates, bytes32 sourceDigest) external;

    function getPolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy);

    function getActivePolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy);
}
