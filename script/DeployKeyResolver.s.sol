// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {KEY_RESOLVER_IMPL_SALT, KEY_RESOLVER_PROXY_SALT} from "./utils/Salt.sol";
import {KeyResolver} from "../src/KeyResolver.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "forge-std/console.sol";

contract DeployKeyResolver is DeploymentConfig {
    function _deployKeyResolverImpl() internal returns (address) {
        KeyResolver impl = new KeyResolver{salt: KEY_RESOLVER_IMPL_SALT}();
        console.log("KeyResolver implementation deployed at:", address(impl));
        writeToJson("KeyResolverImpl", address(impl));
        return address(impl);
    }

    function _deployKeyResolverProxy(address impl) internal returns (address) {
        if (impl == address(0)) {
            impl = _deployKeyResolverImpl();
        }

        address owner = vm.envAddress("OWNER");
        bytes memory initData = abi.encodeCall(KeyResolver.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: KEY_RESOLVER_PROXY_SALT}(impl, initData);
        console.log("KeyResolver proxy deployed at:", address(proxy));
        writeToJson("KeyResolver", address(proxy));
        return address(proxy);
    }

    function _upgradeKeyResolver(address impl, bytes memory data) internal {
        if (impl == address(0)) {
            impl = _deployKeyResolverImpl();
        }

        address proxy = readContractAddress("KeyResolver");
        UUPSUpgradeable(proxy).upgradeToAndCall(impl, data);
        writeToJson("KeyResolverImpl", impl);
    }

    function deployKeyResolverImpl() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployKeyResolverImpl();
        vm.stopBroadcast();
    }

    function deployKeyResolverProxy(address impl) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployKeyResolverProxy(impl);
        vm.stopBroadcast();
    }

    function upgradeKeyResolver(address impl, bytes memory data) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _upgradeKeyResolver(impl, data);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployKeyResolverProxy(address(0));
    }
}
