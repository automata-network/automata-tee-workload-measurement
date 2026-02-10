// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploySignatureVerifier} from "./DeploySignatureVerifier.s.sol";
import {DeployTeeVerifier} from "./DeployTeeVerifier.s.sol";
import {DeployBaseImageRegistry} from "./DeployBaseImageRegistry.s.sol";
import {DeployWorkloadRegistry} from "./DeployWorkloadRegistry.s.sol";
import {DeployKeyResolver} from "./DeployKeyResolver.s.sol";
import {DeploySessionRegistry} from "./DeploySessionRegistry.s.sol";
import "forge-std/console.sol";

/// @title DeployProd
/// @notice Deploys all contracts using existing Automata attestation contracts
/// @dev Requires environment variables:
///      - DCAP_ATTESTATION_ADDR: Automata DCAP attestation contract address
///      - SNP_ATTESTATION_ADDR: Automata SNP attestation contract address
///      - TPM_ATTESTATION_ADDR: Automata TPM attestation contract address
///      - OWNER: Deployer address (also used as initial owner)
///
/// Usage:
///      source .env
///      forge script script/DeployProd.s.sol:DeployProd --rpc-url $RPC_URL --broadcast --verify
contract DeployProd is
    DeploySignatureVerifier,
    DeployTeeVerifier,
    DeployBaseImageRegistry,
    DeployWorkloadRegistry,
    DeployKeyResolver,
    DeploySessionRegistry
{
    function run()
        public
        override(
            DeploySignatureVerifier,
            DeployTeeVerifier,
            DeployBaseImageRegistry,
            DeployWorkloadRegistry,
            DeployKeyResolver,
            DeploySessionRegistry
        )
    {
        console.log("=== Production Deployment ===");

        // 1. Immutable contracts first
        deploySignatureVerifier();
        deployTeeVerifier();

        // 2. Proxy registries (read deps from JSON written above)
        deployBaseImageRegistryProxy(address(0));
        deployWorkloadRegistryProxy(address(0));
        deployKeyResolverProxy(address(0));

        // 3. SessionRegistry last (depends on all others)
        deploySessionRegistryProxy(address(0));

        console.log("");
        console.log("=== Deployment Complete ===");
    }
}
