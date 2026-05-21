// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {AK_COLLATERAL_VERIFIER_SALT} from "./utils/Salt.sol";
import {AkCollateralVerifier} from "../src/bases/AkCollateralVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IMaaKeyRegistry} from "../src/interfaces/registries/IMaaKeyRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import "forge-std/console.sol";

contract DeployAkCollateralVerifier is DeploymentConfig {
    function _deployAkCollateralVerifier() internal returns (address) {
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        address maaKeyRegistryAddr = readContractAddress("MaaKeyRegistry");
        address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");

        console.log("Using SignatureVerifier at:", signatureVerifierAddr);
        console.log("Using MaaKeyRegistry at:", maaKeyRegistryAddr);
        console.log("Using TPM attestation at:", tpmAttestationAddr);

        AkCollateralVerifier verifier = new AkCollateralVerifier{salt: AK_COLLATERAL_VERIFIER_SALT}(
            IMaaKeyRegistry(maaKeyRegistryAddr),
            ISignatureVerifier(signatureVerifierAddr),
            ITpmAttestation(tpmAttestationAddr)
        );
        console.log("AkCollateralVerifier deployed at:", address(verifier));
        writeToJson("AkCollateralVerifier", address(verifier));
        return address(verifier);
    }

    function deployAkCollateralVerifier() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployAkCollateralVerifier();
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployAkCollateralVerifier();
    }
}
