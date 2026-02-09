// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {SESSION_REGISTRY_IMPL_SALT, SESSION_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";

contract DeploySessionRegistry is DeploymentConfig {
    function run() public {
        // Read previously deployed contract addresses from JSON
        address teeVerifierAddr = readContractAddress("TeeVerifier");
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        address baseImageRegistryAddr = readContractAddress("BaseImageRegistry");
        address workloadRegistryAddr = readContractAddress("WorkloadRegistry");

        console.log("Using TeeVerifier at:", teeVerifierAddr);
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);
        console.log("Using BaseImageRegistry at:", baseImageRegistryAddr);
        console.log("Using WorkloadRegistry at:", workloadRegistryAddr);

        // Read attestation contract addresses from environment
        address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");

        console.log("Using TPM attestation at:", tpmAttestationAddr);

        // Get owner address from environment
        address owner = vm.envAddress("OWNER");

        // Start broadcast
        vm.startBroadcast(owner);

        // Deploy implementation
        SessionRegistry impl = new SessionRegistry{salt: SESSION_REGISTRY_IMPL_SALT}(
            ITeeVerifier(teeVerifierAddr),
            ITpmAttestation(tpmAttestationAddr),
            ISignatureVerifier(signatureVerifierAddr),
            IBaseImageRegistry(baseImageRegistryAddr),
            IWorkloadRegistry(workloadRegistryAddr)
        );
        console.log("SessionRegistry implementation deployed at:", address(impl));

        // Deploy proxy with initialize call
        bytes memory initData = abi.encodeCall(SessionRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: SESSION_REGISTRY_PROXY_SALT}(address(impl), initData);
        console.log("SessionRegistry proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Persist PROXY address to JSON (this is the canonical address)
        writeToJson("SessionRegistry", address(proxy));
    }
}
