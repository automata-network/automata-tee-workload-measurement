// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";

/// @title DeployBase
/// @notice Base deployment script with shared logic
abstract contract DeployBase is Script, DeploymentConfig {
    // Deployed contract instances
    SignatureVerifier public signatureVerifier;
    BaseImageRegistry public baseImageRegistry;
    WorkloadRegistry public workloadRegistry;
    SessionRegistry public sessionRegistry;

    // External dependencies (to be set by child contracts)
    IDcapAttestation public dcapAttestation;
    ISnpAttestation public snpAttestation;
    ITpmAttestation public tpmAttestation;
    address public p256Verifier;

    /// @notice Deploy all contracts in order
    function _deployAll() internal {
        console.log("=== Deploying TEE Workload Attestation Contracts ===");
        console.log("Chain ID:", block.chainid);
        console.log("");

        // Step 1: Deploy SignatureVerifier
        _deploySignatureVerifier();

        // Step 2: Deploy BaseImageRegistry
        _deployBaseImageRegistry();

        // Step 3: Deploy WorkloadRegistry
        _deployWorkloadRegistry();

        // Step 4: Deploy SessionRegistry
        _deploySessionRegistry();

        // Write all addresses to JSON
        _writeDeploymentAddresses();

        console.log("");
        console.log("=== Deployment Complete ===");
    }

    function _deploySignatureVerifier() internal {
        console.log("Deploying SignatureVerifier...");
        console.log("  P256 Verifier:", p256Verifier);

        signatureVerifier = new SignatureVerifier(p256Verifier);

        console.log("  SignatureVerifier:", address(signatureVerifier));
    }

    function _deployBaseImageRegistry() internal {
        console.log("Deploying BaseImageRegistry...");

        baseImageRegistry = new BaseImageRegistry(signatureVerifier);

        console.log("  BaseImageRegistry:", address(baseImageRegistry));
    }

    function _deployWorkloadRegistry() internal {
        console.log("Deploying WorkloadRegistry...");

        workloadRegistry = new WorkloadRegistry(signatureVerifier);

        console.log("  WorkloadRegistry:", address(workloadRegistry));
    }

    function _deploySessionRegistry() internal {
        console.log("Deploying SessionRegistry...");
        console.log("  DCAP Attestation:", address(dcapAttestation));
        console.log("  SNP Attestation:", address(snpAttestation));
        console.log("  TPM Attestation:", address(tpmAttestation));

        sessionRegistry = new SessionRegistry(
            dcapAttestation,
            snpAttestation,
            tpmAttestation,
            signatureVerifier,
            baseImageRegistry,
            workloadRegistry
        );

        console.log("  SessionRegistry:", address(sessionRegistry));
    }

    function _writeDeploymentAddresses() internal {
        writeToJson("SignatureVerifier", address(signatureVerifier));
        writeToJson("BaseImageRegistry", address(baseImageRegistry));
        writeToJson("WorkloadRegistry", address(workloadRegistry));
        writeToJson("SessionRegistry", address(sessionRegistry));

        console.log("");
        console.log("Deployment addresses written to deployment/{chainId}.json");
    }
}
