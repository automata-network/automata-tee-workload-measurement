// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script} from "forge-std/Script.sol";
import {
    IAmdSnpSecurityPolicyRegistry,
    AmdSnpSecurityPolicyUpdate
} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";

/// @notice Loads a reviewed AMD SEV-SNP security-policy file into the registry.
/// @dev The JSON file has a top-level `policies` array whose entries use the
///      AmdSnpSecurityPolicyUpdate field names. Entries must be sorted by CPUID.
contract UpdateAmdSnpSecurityPolicies is Script {
    function run() external {
        address registryAddress = vm.envAddress("AMD_SNP_SECURITY_POLICY_REGISTRY");
        string memory policyPath = vm.envString("AMD_SNP_SECURITY_POLICY_FILE");
        string memory policyJson = vm.readFile(policyPath);
        AmdSnpSecurityPolicyUpdate[] memory policies =
            abi.decode(vm.parseJson(policyJson, ".policies"), (AmdSnpSecurityPolicyUpdate[]));

        vm.startBroadcast();
        IAmdSnpSecurityPolicyRegistry(registryAddress).updatePolicies(policies, keccak256(bytes(policyJson)));
        vm.stopBroadcast();
    }
}
