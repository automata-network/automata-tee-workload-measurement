// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploySignatureVerifier} from "./DeploySignatureVerifier.s.sol";
import {DeployTeeVerifier} from "./DeployTeeVerifier.s.sol";
import {DeployTpmVerifier} from "./DeployTpmVerifier.s.sol";
import {DeployZkVerifierRegistry} from "./DeployZkVerifierRegistry.s.sol";
import {DeployBaseImageRegistry} from "./DeployBaseImageRegistry.s.sol";
import {DeployWorkloadRegistry} from "./DeployWorkloadRegistry.s.sol";
import {DeployKeyResolver} from "./DeployKeyResolver.s.sol";
import {DeployMaaKeyRegistry} from "./DeployMaaKeyRegistry.s.sol";
import {DeployAkCollateralVerifier} from "./DeployAkCollateralVerifier.s.sol";
import {DeploySessionRegistry} from "./DeploySessionRegistry.s.sol";
import {DeployAmdSnpSecurityPolicyRegistry} from "./DeployAmdSnpSecurityPolicyRegistry.s.sol";
import "forge-std/console.sol";

/// @title DeployProd
/// @notice Deploys all contracts using existing Automata attestation contracts
/// @dev Requires environment variables:
///      - DCAP_ATTESTATION_ADDR: Automata DCAP attestation contract address
///      - SNP_ATTESTATION_ADDR: Automata SNP attestation contract address
///      - TPM_ATTESTATION_ADDR: Automata TPM attestation contract address
///      - OWNER: Deployer address (also used as initial owner)
///      - AWS_NITRO_ROOT_CERT_HASH: Keccak-256 hash of trusted AWS NitroTPM root certificate DER
///
/// Usage:
///      source .env
///      forge script script/DeployProd.s.sol:DeployProd --rpc-url $RPC_URL --broadcast --verify
contract DeployProd is
    DeploySignatureVerifier,
    DeployZkVerifierRegistry,
    DeployTeeVerifier,
    DeployTpmVerifier,
    DeployBaseImageRegistry,
    DeployWorkloadRegistry,
    DeployKeyResolver,
    DeployMaaKeyRegistry,
    DeployAkCollateralVerifier,
    DeployAmdSnpSecurityPolicyRegistry,
    DeploySessionRegistry
{
    function run()
        public
        override(
            DeploySignatureVerifier,
            DeployZkVerifierRegistry,
            DeployTeeVerifier,
            DeployTpmVerifier,
            DeployBaseImageRegistry,
            DeployWorkloadRegistry,
            DeployKeyResolver,
            DeployMaaKeyRegistry,
            DeployAkCollateralVerifier,
            DeployAmdSnpSecurityPolicyRegistry,
            DeploySessionRegistry
        )
    {
        console.log("=== Production Deployment ===");

        // 1. Immutable contracts first
        deploySignatureVerifier();
        deployZkVerifierRegistry();
        deployTeeVerifier();
        deployTpmVerifier();

        // 2. Proxy registries (read deps from JSON written above)
        deployBaseImageRegistryProxy(address(0));
        deployWorkloadRegistryProxy(address(0));
        deployKeyResolverProxy(address(0));
        deployMaaKeyRegistryProxy(address(0));
        deployAkCollateralVerifier();
        deployAmdSnpSecurityPolicyRegistryProxy(address(0));

        // 3. SessionRegistry last (depends on all others)
        deploySessionRegistryProxy(address(0));

        console.log("");
        console.log("=== Deployment Complete ===");
    }
}
