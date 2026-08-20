// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {TEE_VERIFIER_SALT} from "./utils/Salt.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import "forge-std/console.sol";

contract DeployTeeVerifier is DeploymentConfig {
    function _deployTeeVerifier() internal returns (address) {
        address dcapAttestationAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
        address snpAttestationAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
        bytes32 tdxProgramIdentifier = vm.envBytes32("TDX_DCAP_PROGRAM_IDENTIFIER");
        bytes32 snpProgramIdentifier = vm.envBytes32("AMD_SEV_SNP_PROGRAM_IDENTIFIER");

        console.log("Using DCAP attestation at:", dcapAttestationAddr);
        console.log("Using SNP attestation at:", snpAttestationAddr);

        TeeVerifier teeVerifier = new TeeVerifier{salt: TEE_VERIFIER_SALT}(
            IDcapAttestation(dcapAttestationAddr),
            ISnpAttestation(snpAttestationAddr),
            tdxProgramIdentifier,
            snpProgramIdentifier
        );
        console.log("TeeVerifier deployed at:", address(teeVerifier));
        writeToJson("TeeVerifier", address(teeVerifier));
        return address(teeVerifier);
    }

    function deployTeeVerifier() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployTeeVerifier();
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployTeeVerifier();
    }
}
