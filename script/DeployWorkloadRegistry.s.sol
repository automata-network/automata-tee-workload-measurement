// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {WORKLOAD_REGISTRY_IMPL_SALT, WORKLOAD_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";

contract DeployWorkloadRegistry is DeploymentConfig {
    function run() public {
        // Read previously deployed SignatureVerifier address from JSON
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);

        // Get owner address from environment
        address owner = vm.envAddress("OWNER");

        // Start broadcast
        vm.startBroadcast(owner);

        // Deploy implementation
        WorkloadRegistry impl =
            new WorkloadRegistry{salt: WORKLOAD_REGISTRY_IMPL_SALT}(ISignatureVerifier(signatureVerifierAddr));
        console.log("WorkloadRegistry implementation deployed at:", address(impl));

        // Deploy proxy with initialize call
        bytes memory initData = abi.encodeCall(WorkloadRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: WORKLOAD_REGISTRY_PROXY_SALT}(address(impl), initData);
        console.log("WorkloadRegistry proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Persist PROXY address to JSON (this is the canonical address)
        writeToJson("WorkloadRegistry", address(proxy));
    }
}
