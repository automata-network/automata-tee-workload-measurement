// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploySignatureVerifier} from "./DeploySignatureVerifier.s.sol";
import {DeployTeeVerifier} from "./DeployTeeVerifier.s.sol";
import {DeployBaseImageRegistry} from "./DeployBaseImageRegistry.s.sol";
import {DeployWorkloadRegistry} from "./DeployWorkloadRegistry.s.sol";
import {DeployMaaKeyRegistry} from "./DeployMaaKeyRegistry.s.sol";
import {DeployKeyResolver} from "./DeployKeyResolver.s.sol";
import {DeployAkCollateralVerifier} from "./DeployAkCollateralVerifier.s.sol";
import {DeploySessionRegistry} from "./DeploySessionRegistry.s.sol";
import "forge-std/console.sol";

/// @title DeployFork
/// @notice Deploys the *real* contract stack against a Hoodi-forked Anvil.
///         The fork preserves Hoodi's already-deployed Automata DCAP / SNP / TPM
///         attestation contracts (read from env: DCAP_ATTESTATION_ADDR,
///         SNP_ATTESTATION_ADDR, TPM_ATTESTATION_ADDR), so this script only
///         deploys the new-stack contracts on top.
///
/// Usage (after anvil --fork-url <hoodi-rpc>):
///   export OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
///   export DCAP_ATTESTATION_ADDR=0xaDdeC7e85c2182202b66E331f2a4A0bBB2cEEa1F
///   export SNP_ATTESTATION_ADDR=0x89981202BDd1d19Cb5AfaFe74c847b87982b6B9C
///   export TPM_ATTESTATION_ADDR=0x715e8A7B3E24C0a27dE09b6eaD7e13B2A797cf8B
///   export RPC_URL=http://<anvil-host>:8545
///   ~/.foundry/bin/forge script script/DeployFork.s.sol:DeployFork \
///       --rpc-url $RPC_URL --broadcast --private-key <key> --ffi \
///       --disable-code-size-limit --non-interactive
contract DeployFork is
    DeploySignatureVerifier,
    DeployTeeVerifier,
    DeployBaseImageRegistry,
    DeployWorkloadRegistry,
    DeployMaaKeyRegistry,
    DeployKeyResolver,
    DeployAkCollateralVerifier,
    DeploySessionRegistry
{
    function run()
        public
        override(
            DeploySignatureVerifier,
            DeployTeeVerifier,
            DeployBaseImageRegistry,
            DeployWorkloadRegistry,
            DeployMaaKeyRegistry,
            DeployKeyResolver,
            DeployAkCollateralVerifier,
            DeploySessionRegistry
        )
    {
        console.log("=== Fork Deployment (real verifiers from Hoodi) ===");
        console.log("chainid:", block.chainid);

        // 1. Immutable contracts (TeeVerifier wraps real DCAP/SNP from fork)
        deploySignatureVerifier();
        deployTeeVerifier();

        // 2. Proxy registries (read deps from JSON written above)
        deployBaseImageRegistryProxy(address(0));
        deployWorkloadRegistryProxy(address(0));
        deployMaaKeyRegistryProxy(address(0));
        deployKeyResolverProxy(address(0));
        deployAkCollateralVerifier();

        // 3. SessionRegistry last (depends on all others + real TPM_ATTESTATION_ADDR)
        deploySessionRegistryProxy(address(0));

        console.log("=== Deployment Complete ===");
    }
}
