// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script} from "forge-std/Script.sol";
import {
    IAmdSnpSecurityPolicyRegistry,
    AmdSnpSecurityPolicyUpdate
} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";

/// @dev Foundry encodes JSON object fields in alphabetical order. Keep this
///      JSON-only tuple in that exact order, then convert it to the contract
///      struct whose ABI field order is different.
struct AmdSnpSecurityPolicyJson {
    bool active;
    uint24 cpuid;
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    uint64 revision;
}

/// @notice Loads a reviewed AMD SEV-SNP security-policy file into the registry.
/// @dev The JSON file has a top-level `policies` array whose entries use the
///      AmdSnpSecurityPolicyUpdate field names. Entries must be sorted by CPUID.
contract UpdateAmdSnpSecurityPolicies is Script {
    function _parsePolicyUpdates(string memory policyJson)
        internal
        view
        returns (AmdSnpSecurityPolicyUpdate[] memory policies)
    {
        AmdSnpSecurityPolicyJson[] memory parsed =
            abi.decode(vm.parseJson(policyJson, ".policies"), (AmdSnpSecurityPolicyJson[]));
        policies = new AmdSnpSecurityPolicyUpdate[](parsed.length);
        for (uint256 i = 0; i < parsed.length; i++) {
            policies[i] = AmdSnpSecurityPolicyUpdate({
                cpuid: parsed[i].cpuid,
                revision: parsed[i].revision,
                active: parsed[i].active,
                minimumTcb: parsed[i].minimumTcb,
                platformInfoPolicy: parsed[i].platformInfoPolicy
            });
        }
    }

    function run() external {
        address registryAddress = vm.envAddress("AMD_SNP_SECURITY_POLICY_REGISTRY");
        string memory policyPath = vm.envString("AMD_SNP_SECURITY_POLICY_FILE");
        string memory policyJson = vm.readFile(policyPath);
        AmdSnpSecurityPolicyUpdate[] memory policies = _parsePolicyUpdates(policyJson);

        vm.startBroadcast();
        IAmdSnpSecurityPolicyRegistry(registryAddress).updatePolicies(policies, keccak256(bytes(policyJson)));
        vm.stopBroadcast();
    }
}
