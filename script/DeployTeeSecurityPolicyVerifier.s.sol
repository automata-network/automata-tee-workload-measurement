// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {TEE_SECURITY_POLICY_VERIFIER_SALT} from "./utils/Salt.sol";
import {TeeSecurityPolicyVerifier} from "../src/TeeSecurityPolicyVerifier.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import "forge-std/console.sol";

contract DeployTeeSecurityPolicyVerifier is DeploymentConfig {
    function _deployTeeSecurityPolicyVerifier() internal returns (address) {
        address amdSnpSecurityPolicyRegistryAddr = readContractAddress("AmdSnpSecurityPolicyRegistry");
        console.log("Using AmdSnpSecurityPolicyRegistry at:", amdSnpSecurityPolicyRegistryAddr);

        TeeSecurityPolicyVerifier verifier = new TeeSecurityPolicyVerifier{salt: TEE_SECURITY_POLICY_VERIFIER_SALT}(
            IAmdSnpSecurityPolicyRegistry(amdSnpSecurityPolicyRegistryAddr)
        );
        console.log("TeeSecurityPolicyVerifier deployed at:", address(verifier));
        writeToJson("TeeSecurityPolicyVerifier", address(verifier));
        return address(verifier);
    }

    function deployTeeSecurityPolicyVerifier() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployTeeSecurityPolicyVerifier();
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployTeeSecurityPolicyVerifier();
    }
}
