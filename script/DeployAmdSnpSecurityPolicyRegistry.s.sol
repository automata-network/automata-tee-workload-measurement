// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";

contract DeployAmdSnpSecurityPolicyRegistry is Script {
    function run() external returns (AmdSnpSecurityPolicyRegistry registry) {
        address initialOwner = vm.envAddress("OWNER");

        vm.startBroadcast();
        AmdSnpSecurityPolicyRegistry implementation = new AmdSnpSecurityPolicyRegistry();
        registry = AmdSnpSecurityPolicyRegistry(
            address(
                new ERC1967Proxy(
                    address(implementation), abi.encodeCall(AmdSnpSecurityPolicyRegistry.initialize, (initialOwner))
                )
            )
        );
        vm.stopBroadcast();

        console.log("AmdSnpSecurityPolicyRegistry implementation:", address(implementation));
        console.log("AmdSnpSecurityPolicyRegistry proxy:", address(registry));
    }
}
