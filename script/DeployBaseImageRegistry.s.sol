// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {BASE_IMAGE_REGISTRY_IMPL_SALT, BASE_IMAGE_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "forge-std/console.sol";

contract DeployBaseImageRegistry is DeploymentConfig {
    function _deployBaseImageRegistryImpl() internal returns (address) {
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);

        BaseImageRegistry impl =
            new BaseImageRegistry{salt: BASE_IMAGE_REGISTRY_IMPL_SALT}(ISignatureVerifier(signatureVerifierAddr));
        console.log("BaseImageRegistry implementation deployed at:", address(impl));
        writeToJson("BaseImageRegistryImpl", address(impl));
        return address(impl);
    }

    function _deployBaseImageRegistryProxy(address impl) internal returns (address) {
        if (impl == address(0)) {
            impl = _deployBaseImageRegistryImpl();
        }

        address owner = vm.envAddress("OWNER");
        bytes memory initData = abi.encodeCall(BaseImageRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: BASE_IMAGE_REGISTRY_PROXY_SALT}(impl, initData);
        console.log("BaseImageRegistry proxy deployed at:", address(proxy));
        writeToJson("BaseImageRegistry", address(proxy));
        return address(proxy);
    }

    function _upgradeBaseImageRegistry(address impl, bytes memory data) internal {
        if (impl == address(0)) {
            impl = _deployBaseImageRegistryImpl();
        }

        address proxy = readContractAddress("BaseImageRegistry");
        UUPSUpgradeable(proxy).upgradeToAndCall(impl, data);
        writeToJson("BaseImageRegistryImpl", impl);
    }

    function deployBaseImageRegistryImpl() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployBaseImageRegistryImpl();
        vm.stopBroadcast();
    }

    function deployBaseImageRegistryProxy(address impl) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployBaseImageRegistryProxy(impl);
        vm.stopBroadcast();
    }

    function upgradeBaseImageRegistry(address impl, bytes memory data) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _upgradeBaseImageRegistry(impl, data);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployBaseImageRegistryProxy(address(0));
    }
}
