// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {KEY_RESOLVER_IMPL_SALT, KEY_RESOLVER_PROXY_SALT} from "./utils/Salt.sol";
import {KeyResolver} from "../src/KeyResolver.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";

contract DeployKeyResolver is DeploymentConfig {
    function run() public {
        // Get owner address from environment
        address owner = vm.envAddress("OWNER");

        // Start broadcast
        vm.startBroadcast(owner);

        // Deploy implementation
        KeyResolver impl = new KeyResolver{salt: KEY_RESOLVER_IMPL_SALT}();
        console.log("KeyResolver implementation deployed at:", address(impl));

        // Deploy proxy with initialize call
        bytes memory initData = abi.encodeCall(KeyResolver.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: KEY_RESOLVER_PROXY_SALT}(address(impl), initData);
        console.log("KeyResolver proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Persist PROXY address to JSON (this is the canonical address)
        writeToJson("KeyResolver", address(proxy));
    }
}
