// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {BASE_IMAGE_REGISTRY_IMPL_SALT, BASE_IMAGE_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";

contract DeployBaseImageRegistry is DeploymentConfig {
    function run() public {
        // Read previously deployed SignatureVerifier address from JSON
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);

        // Get owner address from environment
        address owner = vm.envAddress("OWNER");

        // Start broadcast
        vm.startBroadcast(owner);

        // Deploy implementation
        BaseImageRegistry impl =
            new BaseImageRegistry{salt: BASE_IMAGE_REGISTRY_IMPL_SALT}(ISignatureVerifier(signatureVerifierAddr));
        console.log("BaseImageRegistry implementation deployed at:", address(impl));

        // Deploy proxy with initialize call
        bytes memory initData = abi.encodeCall(BaseImageRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: BASE_IMAGE_REGISTRY_PROXY_SALT}(address(impl), initData);
        console.log("BaseImageRegistry proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Persist PROXY address to JSON (this is the canonical address)
        writeToJson("BaseImageRegistry", address(proxy));
    }
}
