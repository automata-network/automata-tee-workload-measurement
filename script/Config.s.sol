// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {Script, console} from "forge-std/Script.sol";

contract Config is Script, DeploymentConfig {
    // --- Internal helpers (no broadcast) ---

    function _updateBaseImageWhitelist(bytes32 ownerFingerprint, bool whitelisted) internal {
        address registryAddr = readContractAddress("BaseImageRegistry");
        console.log("Using BaseImageRegistry at:", registryAddr);

        BaseImageRegistry registry = BaseImageRegistry(registryAddr);

        if (whitelisted) {
            bytes32[] memory fingerprints = new bytes32[](1);
            fingerprints[0] = ownerFingerprint;
            registry.addToWhitelist(fingerprints);
            console.log("Added fingerprint to BaseImageRegistry whitelist:");
            console.logBytes32(ownerFingerprint);
        } else {
            registry.removeFromWhitelist(ownerFingerprint);
            console.log("Removed fingerprint from BaseImageRegistry whitelist:");
            console.logBytes32(ownerFingerprint);
        }
    }

    function _updateWorkloadWhitelist(bytes32 ownerFingerprint, bool whitelisted) internal {
        address registryAddr = readContractAddress("WorkloadRegistry");
        console.log("Using WorkloadRegistry at:", registryAddr);

        WorkloadRegistry registry = WorkloadRegistry(registryAddr);

        if (whitelisted) {
            bytes32[] memory fingerprints = new bytes32[](1);
            fingerprints[0] = ownerFingerprint;
            registry.addToWhitelist(fingerprints);
            console.log("Added fingerprint to WorkloadRegistry whitelist:");
            console.logBytes32(ownerFingerprint);
        } else {
            registry.removeFromWhitelist(ownerFingerprint);
            console.log("Removed fingerprint from WorkloadRegistry whitelist:");
            console.logBytes32(ownerFingerprint);
        }
    }

    function _enableBaseImageRegistryWhitelist(bool enabled) internal {
        address registryAddr = readContractAddress("BaseImageRegistry");
        console.log("Using BaseImageRegistry at:", registryAddr);

        BaseImageRegistry registry = BaseImageRegistry(registryAddr);
        bool isPaused = registry.paused();

        if (enabled && !isPaused) {
            registry.pause();
            console.log("BaseImageRegistry whitelist enforcement enabled (paused)");
        } else if (!enabled && isPaused) {
            registry.unpause();
            console.log("BaseImageRegistry whitelist enforcement disabled (unpaused)");
        } else {
            console.log("BaseImageRegistry already in desired state (paused:", isPaused, ")");
        }
    }

    function _enableWorkloadRegistryWhitelist(bool enabled) internal {
        address registryAddr = readContractAddress("WorkloadRegistry");
        console.log("Using WorkloadRegistry at:", registryAddr);

        WorkloadRegistry registry = WorkloadRegistry(registryAddr);
        bool isPaused = registry.paused();

        if (enabled && !isPaused) {
            registry.pause();
            console.log("WorkloadRegistry whitelist enforcement enabled (paused)");
        } else if (!enabled && isPaused) {
            registry.unpause();
            console.log("WorkloadRegistry whitelist enforcement disabled (unpaused)");
        } else {
            console.log("WorkloadRegistry already in desired state (paused:", isPaused, ")");
        }
    }

    // --- Public functions (with broadcast) ---

    function updateBaseImageWhitelist(bytes32 ownerFingerprint, bool whitelisted) public {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _updateBaseImageWhitelist(ownerFingerprint, whitelisted);
        vm.stopBroadcast();
    }

    function updateWorkloadWhitelist(bytes32 ownerFingerprint, bool whitelisted) public {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _updateWorkloadWhitelist(ownerFingerprint, whitelisted);
        vm.stopBroadcast();
    }

    function enableBaseImageRegistryWhitelist(bool enabled) public {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _enableBaseImageRegistryWhitelist(enabled);
        vm.stopBroadcast();
    }

    function enableWorkloadRegistryWhitelist(bool enabled) public {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _enableWorkloadRegistryWhitelist(enabled);
        vm.stopBroadcast();
    }
}
