// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {TEE_VERIFIER_SALT} from "./utils/Salt.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import "forge-std/console.sol";

contract DeployTeeVerifier is DeploymentConfig {
    function run() public {
        // Read attestation contract addresses from environment
        address dcapAttestationAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
        address snpAttestationAddr = vm.envAddress("SNP_ATTESTATION_ADDR");

        console.log("Using DCAP attestation at:", dcapAttestationAddr);
        console.log("Using SNP attestation at:", snpAttestationAddr);

        // Start broadcast with OWNER from environment
        vm.startBroadcast(vm.envAddress("OWNER"));

        // Deploy TeeVerifier with CREATE2
        TeeVerifier teeVerifier = new TeeVerifier{salt: TEE_VERIFIER_SALT}(
            IDcapAttestation(dcapAttestationAddr), ISnpAttestation(snpAttestationAddr)
        );

        console.log("TeeVerifier deployed at:", address(teeVerifier));

        vm.stopBroadcast();

        // Persist deployment address to JSON
        writeToJson("TeeVerifier", address(teeVerifier));
    }
}
