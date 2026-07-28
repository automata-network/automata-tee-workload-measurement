// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Attribute, AttributeRequirement} from "../../types/Common.sol";
import {TEEType} from "../../types/Evidence.sol";

struct VerifiedTeePolicyInputs {
    TEEType teeType;
    uint256 enabledTeeAttributes;
    uint256 intelTdxTcbStatusBit;
    bytes32 amdSevSnpTcbValues;
    uint64 amdSevSnpPlatformInfo;
    uint24 amdSevSnpCpuid;
    uint32 amdSevSnpReportVersion;
    uint64 amdSevSnpLaunchMitigationVector;
    uint64 amdSevSnpCurrentMitigationVector;
}

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

    function verifyTeePolicy(
        VerifiedTeePolicyInputs calldata inputs,
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) external view;
}
