// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {SessionRegistry} from "../src/SessionRegistry.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";

contract DeployNm0985GraphUpgrade is Script {
    bytes32 internal constant TEE_VERIFIER_SALT = keccak256("NM_0985_AUDITED_ISOLATED_AMD_TEE_VERIFIER");
    bytes32 internal constant SESSION_REGISTRY_IMPLEMENTATION_SALT =
        keccak256("NM_0985_AUDITED_ISOLATED_AMD_SESSION_REGISTRY_IMPLEMENTATION");

    address internal constant DCAP_ATTESTATION = 0xaDdeC7e85c2182202b66E331f2a4A0bBB2cEEa1F;
    address internal constant TPM_ATTESTATION = 0x715e8A7B3E24C0a27dE09b6eaD7e13B2A797cf8B;
    address internal constant SIGNATURE_VERIFIER = 0x4fa8d26B694F11eA949b058c06581846Ff955344;
    address internal constant AK_COLLATERAL_VERIFIER = 0x0f6eb56bD328afEdC05c5FB325decbBA220ba22c;
    address internal constant BASE_IMAGE_REGISTRY = 0xcB90Ebe2e9f3c8C3f0ADA37895ABEd9429B0BAba;
    address internal constant WORKLOAD_REGISTRY = 0x7f73A7AcFc8144D09E0648B96849972984c07174;
    address internal constant AMD_SNP_SECURITY_POLICY_REGISTRY = 0x1f1b692a435E6d987216754D62B5af719188bE6A;
    address internal constant SESSION_REGISTRY = 0x69D51EBae287E1688f0b920448393100feF1B10e;

    function run() external returns (address teeVerifierAddress, address implementationAddress) {
        address owner = vm.envAddress("OWNER");
        address snpAttestation = vm.envAddress("SNP_ATTESTATION_ADDR");

        vm.startBroadcast(owner);
        TeeVerifier teeVerifier = new TeeVerifier{salt: TEE_VERIFIER_SALT}(
            IDcapAttestation(DCAP_ATTESTATION), ISnpAttestation(snpAttestation)
        );
        SessionRegistry implementation = new SessionRegistry{salt: SESSION_REGISTRY_IMPLEMENTATION_SALT}(
            ITeeVerifier(address(teeVerifier)),
            ITpmAttestation(TPM_ATTESTATION),
            ISignatureVerifier(SIGNATURE_VERIFIER),
            IAkCollateralVerifier(AK_COLLATERAL_VERIFIER),
            IBaseImageRegistry(BASE_IMAGE_REGISTRY),
            IWorkloadRegistry(WORKLOAD_REGISTRY),
            IAmdSnpSecurityPolicyRegistry(AMD_SNP_SECURITY_POLICY_REGISTRY)
        );
        UUPSUpgradeable(SESSION_REGISTRY).upgradeToAndCall(address(implementation), bytes(""));
        vm.stopBroadcast();

        teeVerifierAddress = address(teeVerifier);
        implementationAddress = address(implementation);
        console.log("Audited TeeVerifier:", teeVerifierAddress);
        console.log("Audited SessionRegistry implementation:", implementationAddress);
    }
}
