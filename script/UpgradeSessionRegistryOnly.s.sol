// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {AkCollateralVerifier} from "../src/bases/AkCollateralVerifier.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice Deploys new immutable dependencies and upgrades only an existing
///         SessionRegistry proxy. It does not modify any other proxy.
contract UpgradeSessionRegistryOnly is Script {
    function run() public {
        address proxyAddress = vm.envAddress("SESSION_REGISTRY_PROXY");
        address owner = vm.envAddress("OWNER");
        AmdSnpSecurityPolicyRegistry amdSnpSecurityPolicyRegistry =
            AmdSnpSecurityPolicyRegistry(vm.envAddress("AMD_SNP_SECURITY_POLICY_REGISTRY"));

        SessionRegistry current = SessionRegistry(proxyAddress);
        require(current.owner() == owner, "SessionRegistry owner mismatch");
        require(amdSnpSecurityPolicyRegistry.owner() == owner, "AMD policy registry owner mismatch");

        TeeVerifier currentTeeVerifier = TeeVerifier(address(current.teeVerifier()));
        IDcapAttestation dcapAttestation = currentTeeVerifier.dcapAttestation();
        ISnpAttestation snpAttestation = currentTeeVerifier.snpAttestation();
        ITpmAttestation tpmAttestation = current.tpmAttestation();
        ISignatureVerifier signatureVerifier = current.signatureVerifier();
        IBaseImageRegistry baseImageRegistry = current.baseImageRegistry();
        IWorkloadRegistry workloadRegistry = current.workloadRegistry();
        AkCollateralVerifier currentAkCollateralVerifier = AkCollateralVerifier(address(current.akCollateralVerifier()));

        require(
            address(currentAkCollateralVerifier.signatureVerifier()) == address(signatureVerifier),
            "AK signatureVerifier mismatch"
        );
        require(
            address(currentAkCollateralVerifier.tpmAttestation()) == address(tpmAttestation),
            "AK tpmAttestation mismatch"
        );

        vm.startBroadcast(owner);

        TeeVerifier teeVerifier = new TeeVerifier(
            dcapAttestation,
            snpAttestation,
            vm.envBytes32("TDX_DCAP_PROGRAM_IDENTIFIER"),
            vm.envBytes32("AMD_SEV_SNP_PROGRAM_IDENTIFIER")
        );
        console.log("new TeeVerifier:             ", address(teeVerifier));

        AkCollateralVerifier akCollateralVerifier =
            new AkCollateralVerifier(currentAkCollateralVerifier.maaKeyRegistry(), signatureVerifier, tpmAttestation);
        console.log("new AkCollateralVerifier:    ", address(akCollateralVerifier));

        SessionRegistry implementation = new SessionRegistry(
            ITeeVerifier(address(teeVerifier)),
            tpmAttestation,
            signatureVerifier,
            IAkCollateralVerifier(address(akCollateralVerifier)),
            baseImageRegistry,
            workloadRegistry,
            IAmdSnpSecurityPolicyRegistry(address(amdSnpSecurityPolicyRegistry))
        );
        console.log("new SessionRegistry impl:    ", address(implementation));

        UUPSUpgradeable(proxyAddress).upgradeToAndCall(address(implementation), "");
        console.log("SessionRegistry proxy upgraded:", proxyAddress);

        vm.stopBroadcast();

        SessionRegistry upgraded = SessionRegistry(proxyAddress);
        require(upgraded.owner() == owner, "owner changed");
        require(address(upgraded.teeVerifier()) == address(teeVerifier), "teeVerifier not rewired");
        require(
            address(upgraded.akCollateralVerifier()) == address(akCollateralVerifier),
            "akCollateralVerifier not rewired"
        );
        require(
            address(upgraded.amdSnpSecurityPolicyRegistry()) == address(amdSnpSecurityPolicyRegistry),
            "AMD policy registry not rewired"
        );
        require(address(upgraded.tpmAttestation()) == address(tpmAttestation), "tpmAttestation changed");
        require(address(upgraded.signatureVerifier()) == address(signatureVerifier), "signatureVerifier changed");
        require(address(upgraded.baseImageRegistry()) == address(baseImageRegistry), "baseImageRegistry changed");
        require(address(upgraded.workloadRegistry()) == address(workloadRegistry), "workloadRegistry changed");
    }
}
