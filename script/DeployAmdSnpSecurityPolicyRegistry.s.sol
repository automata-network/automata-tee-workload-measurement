// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/console.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {
    AMD_SNP_SECURITY_POLICY_REGISTRY_IMPL_SALT,
    AMD_SNP_SECURITY_POLICY_REGISTRY_PROXY_SALT
} from "./utils/Salt.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";

contract DeployAmdSnpSecurityPolicyRegistry is DeploymentConfig {
    function _deployAmdSnpSecurityPolicyRegistryImpl() internal returns (address) {
        AmdSnpSecurityPolicyRegistry implementation =
            new AmdSnpSecurityPolicyRegistry{salt: AMD_SNP_SECURITY_POLICY_REGISTRY_IMPL_SALT}();
        console.log("AmdSnpSecurityPolicyRegistry implementation:", address(implementation));
        writeToJson("AmdSnpSecurityPolicyRegistryImpl", address(implementation));
        return address(implementation);
    }

    function _deployAmdSnpSecurityPolicyRegistryProxy(address implementation) internal returns (address) {
        if (implementation == address(0)) {
            implementation = _deployAmdSnpSecurityPolicyRegistryImpl();
        }
        address initialOwner = vm.envAddress("OWNER");
        AmdSnpSecurityPolicyRegistry registry = AmdSnpSecurityPolicyRegistry(
            address(
                new ERC1967Proxy{salt: AMD_SNP_SECURITY_POLICY_REGISTRY_PROXY_SALT}(
                    address(implementation), abi.encodeCall(AmdSnpSecurityPolicyRegistry.initialize, (initialOwner))
                )
            )
        );
        console.log("AmdSnpSecurityPolicyRegistry proxy:", address(registry));
        writeToJson("AmdSnpSecurityPolicyRegistry", address(registry));
        return address(registry);
    }

    function deployAmdSnpSecurityPolicyRegistryProxy(address implementation) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployAmdSnpSecurityPolicyRegistryProxy(implementation);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployAmdSnpSecurityPolicyRegistryProxy(address(0));
    }
}
