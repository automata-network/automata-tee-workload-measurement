// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Attribute, AttributeRequirement} from "../types/Common.sol";
import {TEEType} from "../types/Evidence.sol";
import {IAmdSnpSecurityPolicyRegistry} from "./registries/IAmdSnpSecurityPolicyRegistry.sol";

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

interface ITeeSecurityPolicyVerifier {
    function amdSnpSecurityPolicyRegistry() external view returns (IAmdSnpSecurityPolicyRegistry);

    function verifyTeePolicy(
        VerifiedTeePolicyInputs calldata inputs,
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) external view;
}
