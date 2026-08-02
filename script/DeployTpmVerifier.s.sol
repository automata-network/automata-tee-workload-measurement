// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {TPM_VERIFIER_SALT} from "./utils/Salt.sol";
import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import "forge-std/console.sol";

contract DeployTpmVerifier is DeploymentConfig {
    function _deployTpmVerifier() internal returns (address) {
        address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
        address zkVerifierRegistryAddr = readContractAddress("ZkVerifierRegistry");

        console.log("Using TPM attestation at:", tpmAttestationAddr);
        console.log("Using ZkVerifierRegistry at:", zkVerifierRegistryAddr);

        TpmVerifier verifier = new TpmVerifier{salt: TPM_VERIFIER_SALT}(
            ITpmAttestation(tpmAttestationAddr), IZkVerifierRegistry(zkVerifierRegistryAddr)
        );
        console.log("TpmVerifier deployed at:", address(verifier));
        writeToJson("TpmVerifier", address(verifier));
        return address(verifier);
    }

    function deployTpmVerifier() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployTpmVerifier();
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployTpmVerifier();
    }
}
