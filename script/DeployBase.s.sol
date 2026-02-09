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
import {TeeVerifier} from "../src/TeeVerifier.sol";

/// @title DeployBase
/// @notice Base deployment script with shared logic
abstract contract DeployBase is Script, DeploymentConfig {
    // Deployed contract instances
    SignatureVerifier public signatureVerifier;
    TeeVerifier public teeVerifier;
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

        // Step 2: Deploy TeeVerifier
        _deployTeeVerifier();

        // Step 3: Deploy BaseImageRegistry
        _deployBaseImageRegistry();

        // Step 4: Deploy WorkloadRegistry
        _deployWorkloadRegistry();

        // Step 5: Deploy SessionRegistry
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

    function _deployTeeVerifier() internal {
        console.log("Deploying TeeVerifier...");
        console.log("  DCAP Attestation:", address(dcapAttestation));
        console.log("  SNP Attestation:", address(snpAttestation));

        teeVerifier = new TeeVerifier(dcapAttestation, snpAttestation);

        console.log("  TeeVerifier:", address(teeVerifier));
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
        console.log("  TEE Verifier:", address(teeVerifier));
        console.log("  TPM Attestation:", address(tpmAttestation));

        sessionRegistry =
            new SessionRegistry(teeVerifier, tpmAttestation, signatureVerifier, baseImageRegistry, workloadRegistry);

        console.log("  SessionRegistry:", address(sessionRegistry));
    }

    function _writeDeploymentAddresses() internal {
        writeToJson("SignatureVerifier", address(signatureVerifier));
        writeToJson("TeeVerifier", address(teeVerifier));
        writeToJson("BaseImageRegistry", address(baseImageRegistry));
        writeToJson("WorkloadRegistry", address(workloadRegistry));
        writeToJson("SessionRegistry", address(sessionRegistry));

        console.log("");
        console.log("Deployment addresses written to deployment/{chainId}.json");
    }
}
