// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console} from "forge-std/console.sol";
import {DeploymentConfig} from "../utils/DeploymentConfig.sol";
import "../utils/Salt.sol";

import {CVMRegistry} from "../../src/usecases/CVMRegistry.sol";

contract DeployCVM is DeploymentConfig {
    address owner = vm.envAddress("OWNER");
    address workloadVerifier = readContractAddress("WorkloadVerifierProxy");

    function run() public {
        deployCVMRegistry();
    }

    function deployCVMRegistryImpl() public returns (address implAddress) {
        // deploy the CVMRegistry implementation
        vm.broadcast(owner);
        CVMRegistry registry = new CVMRegistry{salt: CVM_REGISTRY_IMPL_SALT}(workloadVerifier);
        implAddress = address(registry);

        console.log("CVMRegistry implementation deployed at:", implAddress);

        // write the implementation address to JSON
        writeToJson("CVMRegistryImpl", implAddress);
    }

    function deployCVMRegistry() public {
        // deploy the CVMRegistry implementation
        address implAddress = deployCVMRegistryImpl();

        // deploy the CVMRegistry proxy
        vm.broadcast(owner);
        ERC1967Proxy CVMRegistryProxy = new ERC1967Proxy{salt: CVM_REGISTRY_PROXY_SALT}(
            implAddress, abi.encodeWithSelector(CVMRegistry.initialize.selector, owner)
        );
        address proxyAddress = address(CVMRegistryProxy);

        console.log("CVMRegistry proxy deployed at:", proxyAddress);

        // write the proxy address to JSON
        writeToJson("CVMRegistryProxy", proxyAddress);
    }

    function upgradeCVMRegistry(address newImpl, bytes memory data) public {
        // Check if the proxy exists
        CVMRegistry CVMRegistryProxy = CVMRegistry(payable(readContractAddress("CVMRegistryProxy")));

        // deploy the new implementation
        if (newImpl == address(0)) {
            newImpl = deployCVMRegistryImpl();
        }

        // upgrade the proxy to the new implementation
        vm.broadcast(owner);
        CVMRegistryProxy.upgradeToAndCall(newImpl, data);

        console.log("CVMRegistry upgraded to new implementation at:", newImpl);
    }
}
