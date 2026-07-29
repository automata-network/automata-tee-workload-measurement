// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploySignatureVerifier} from "./DeploySignatureVerifier.s.sol";
import {DeployBaseImageRegistry} from "./DeployBaseImageRegistry.s.sol";
import {DeployWorkloadRegistry} from "./DeployWorkloadRegistry.s.sol";
import {DeployMaaKeyRegistry} from "./DeployMaaKeyRegistry.s.sol";
import {DeployMock} from "./DeployMock.s.sol";
import {DeployAmdSnpSecurityPolicyRegistry} from "./DeployAmdSnpSecurityPolicyRegistry.s.sol";
import "forge-std/console.sol";

/// @title DeployTestnet
/// @notice One-shot deploy of the full mock-backed stack onto a fresh testnet
///         (e.g. Anvil). Bundles SignatureVerifier + BaseImage/Workload/MaaKey
///         registries + DeployMock (mock attestation contracts + SessionRegistry
///         with mock TEE/TPM but real signature verification).
///
/// Usage:
///   export OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  # anvil default[0]
///   export RPC_URL=http://<anvil-host>:8545
///   ~/.foundry/bin/forge script script/DeployTestnet.s.sol:DeployTestnet \
///       --rpc-url $RPC_URL --broadcast \
///       --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///       --ffi
contract DeployTestnet is
    DeploySignatureVerifier,
    DeployBaseImageRegistry,
    DeployWorkloadRegistry,
    DeployMaaKeyRegistry,
    DeployAmdSnpSecurityPolicyRegistry,
    DeployMock
{
    function run()
        public
        override(
            DeploySignatureVerifier,
            DeployBaseImageRegistry,
            DeployWorkloadRegistry,
            DeployMaaKeyRegistry,
            DeployAmdSnpSecurityPolicyRegistry,
            DeployMock
        )
    {
        console.log("=== Testnet Deployment (mock stack) ===");
        console.log("chainid:", block.chainid);

        // 1. Immutable contracts first
        deploySignatureVerifier();

        // 2. Proxy registries
        deployBaseImageRegistryProxy(address(0));
        deployWorkloadRegistryProxy(address(0));
        deployMaaKeyRegistryProxy(address(0));
        deployAmdSnpSecurityPolicyRegistryProxy(address(0));

        // 3. Mock attestation + SessionRegistry (depends on all of the above)
        deployMock();

        console.log("=== Deployment Complete ===");
    }
}
