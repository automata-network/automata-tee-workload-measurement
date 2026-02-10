// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {MockAutomataDcapAttestation} from "../src/mock/MockAutomataDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "../src/mock/MockAutomataSnpAttestation.sol";
import {TeeVerifier, ITeeVerifier} from "../src/TeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";

contract DeployMock is Script, DeploymentConfig {
    // uint256 privateKey = vm.envUint("PRIVATE_KEY");
    // address deployer = vm.addr(privateKey);

    function run() public {
        vm.startBroadcast();

        console.log("=== Mock Deployment ===");

        MockAutomataDcapAttestation dcapAttestation = new MockAutomataDcapAttestation();
        console.log("MockAutomataDcapAttestation deployed at:", address(dcapAttestation));

        MockAutomataSnpAttestation snpAttestation = new MockAutomataSnpAttestation();
        console.log("MockAutomataSnpAttestation deployed at:", address(snpAttestation));

        TeeVerifier teeVerifier = new TeeVerifier(
            dcapAttestation,
            snpAttestation
        );
        console.log("TeeVerifier deployed at:", address(teeVerifier));
        writeToJson("TeeVerifierMock", address(teeVerifier));

        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        address baseImageRegistryAddr = readContractAddress("BaseImageRegistry");
        address workloadRegistryAddr = readContractAddress("WorkloadRegistry");
        address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
        SessionRegistry sessionRegistry = new SessionRegistry(
            ITeeVerifier(address(teeVerifier)),
            ITpmAttestation(tpmAttestationAddr),
            ISignatureVerifier(signatureVerifierAddr),
            IBaseImageRegistry(baseImageRegistryAddr),
            IWorkloadRegistry(workloadRegistryAddr)
        );
        console.log("SessionRegistry deployed at:", address(sessionRegistry));
        writeToJson("SessionRegistryMock", address(sessionRegistry));

        console.log("");
        console.log("=== Deployment Complete ===");
        vm.stopBroadcast();
    }
}
