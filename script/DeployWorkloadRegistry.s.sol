// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {WORKLOAD_REGISTRY_IMPL_SALT, WORKLOAD_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "forge-std/console.sol";

contract DeployWorkloadRegistry is DeploymentConfig {
    function _deployWorkloadRegistryImpl() internal returns (address) {
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);

        WorkloadRegistry impl =
            new WorkloadRegistry{salt: WORKLOAD_REGISTRY_IMPL_SALT}(ISignatureVerifier(signatureVerifierAddr));
        console.log("WorkloadRegistry implementation deployed at:", address(impl));
        writeToJson("WorkloadRegistryImpl", address(impl));
        return address(impl);
    }

    function _deployWorkloadRegistryProxy(address impl) internal returns (address) {
        if (impl == address(0)) {
            impl = _deployWorkloadRegistryImpl();
        }

        address owner = vm.envAddress("OWNER");
        bytes memory initData = abi.encodeCall(WorkloadRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: WORKLOAD_REGISTRY_PROXY_SALT}(impl, initData);
        console.log("WorkloadRegistry proxy deployed at:", address(proxy));
        writeToJson("WorkloadRegistry", address(proxy));
        return address(proxy);
    }

    function _upgradeWorkloadRegistry(address impl, bytes memory data) internal {
        if (impl == address(0)) {
            impl = _deployWorkloadRegistryImpl();
        }

        address proxy = readContractAddress("WorkloadRegistry");
        UUPSUpgradeable(proxy).upgradeToAndCall(impl, data);
        writeToJson("WorkloadRegistryImpl", impl);
    }

    function deployWorkloadRegistryImpl() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployWorkloadRegistryImpl();
        vm.stopBroadcast();
    }

    function deployWorkloadRegistryProxy(address impl) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployWorkloadRegistryProxy(impl);
        vm.stopBroadcast();
    }

    function upgradeWorkloadRegistry(address impl, bytes memory data) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _upgradeWorkloadRegistry(impl, data);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployWorkloadRegistryProxy(address(0));
    }
}
