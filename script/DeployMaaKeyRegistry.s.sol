// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {MAA_KEY_REGISTRY_IMPL_SALT, MAA_KEY_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {MaaKeyRegistry} from "../src/MaaKeyRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "forge-std/console.sol";

/// @title DeployMaaKeyRegistry
/// @notice Deploys MaaKeyRegistry as an ERC1967 proxy with atomic `initialize(owner)`.
/// @dev The proxy is constructed with the initialize call as its initData, so the deployer
///      cannot lose the initialization race to a front-running attacker. The implementation
///      is UUPS-upgradeable and gated by `onlyOwner` (admin operations also gated by
///      `onlyOwner` — see MaaKeyRegistry.sol). The owner key controls the entire Azure
///      attestation trust anchor; treat it accordingly (multisig / time-locked rotation).
contract DeployMaaKeyRegistry is DeploymentConfig {
    function _deployMaaKeyRegistryImpl() internal returns (address) {
        MaaKeyRegistry impl = new MaaKeyRegistry{salt: MAA_KEY_REGISTRY_IMPL_SALT}();
        console.log("MaaKeyRegistry implementation deployed at:", address(impl));
        writeToJson("MaaKeyRegistryImpl", address(impl));
        return address(impl);
    }

    function _deployMaaKeyRegistryProxy(address impl) internal returns (address) {
        if (impl == address(0)) {
            impl = _deployMaaKeyRegistryImpl();
        }

        address owner = vm.envAddress("OWNER");
        bytes memory initData = abi.encodeCall(MaaKeyRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: MAA_KEY_REGISTRY_PROXY_SALT}(impl, initData);
        console.log("MaaKeyRegistry proxy deployed at:", address(proxy));
        writeToJson("MaaKeyRegistry", address(proxy));
        return address(proxy);
    }

    function _upgradeMaaKeyRegistry(address impl, bytes memory data) internal {
        if (impl == address(0)) {
            impl = _deployMaaKeyRegistryImpl();
        }
        address proxy = readContractAddress("MaaKeyRegistry");
        UUPSUpgradeable(proxy).upgradeToAndCall(impl, data);
        writeToJson("MaaKeyRegistryImpl", impl);
    }

    function deployMaaKeyRegistryImpl() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployMaaKeyRegistryImpl();
        vm.stopBroadcast();
    }

    function deployMaaKeyRegistryProxy(address impl) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployMaaKeyRegistryProxy(impl);
        vm.stopBroadcast();
    }

    function upgradeMaaKeyRegistry(address impl, bytes memory data) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _upgradeMaaKeyRegistry(impl, data);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployMaaKeyRegistryProxy(address(0));
    }
}
