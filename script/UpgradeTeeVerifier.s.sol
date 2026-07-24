// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice One-shot Hoodi upgrade: deploy the verified TEE attribute registry
///         implementations and a fresh TeeVerifier, then UUPS-upgrade all three
///         existing registry proxies in place.
contract UpgradeTeeVerifier is Script {
    address constant SESSION_REGISTRY_PROXY = 0xB247950fBBFCE245641e433AFd7d8884328CE5A1;
    // TeeVerifier deps
    address constant DCAP = 0xaDdeC7e85c2182202b66E331f2a4A0bBB2cEEa1F;
    address constant SNP = 0x89981202BDd1d19Cb5AfaFe74c847b87982b6B9C;
    // Other SessionRegistry impl deps (unchanged)
    address constant TPM = 0x715e8A7B3E24C0a27dE09b6eaD7e13B2A797cf8B;
    address constant SIG_VERIFIER = 0xc52B7390DFb82CC4e2241B4a2586428532D76f18;
    address constant AK_COLL = 0xf66565a927D7c359D24Ac092B4B6871171592089;
    address constant BASE_IMG = 0xCbe56f9B73c822679Cf36DcF8D99434E0f1588Ca;
    address constant WORKLOAD = 0xda6430E06385F7516963f8A3B4e87beBb89860F8;

    function run() public {
        vm.startBroadcast();

        BaseImageRegistry baseImageImpl = new BaseImageRegistry(ISignatureVerifier(SIG_VERIFIER));
        console.log("new BaseImageRegistry impl:", address(baseImageImpl));

        WorkloadRegistry workloadImpl = new WorkloadRegistry(ISignatureVerifier(SIG_VERIFIER));
        console.log("new WorkloadRegistry impl: ", address(workloadImpl));

        TeeVerifier tee = new TeeVerifier(IDcapAttestation(DCAP), ISnpAttestation(SNP));
        console.log("new TeeVerifier:        ", address(tee));

        SessionRegistry sessionImpl = new SessionRegistry(
            ITeeVerifier(address(tee)),
            ITpmAttestation(TPM),
            ISignatureVerifier(SIG_VERIFIER),
            IAkCollateralVerifier(AK_COLL),
            IBaseImageRegistry(BASE_IMG),
            IWorkloadRegistry(WORKLOAD)
        );
        console.log("new SessionRegistry impl:", address(sessionImpl));

        UUPSUpgradeable(BASE_IMG).upgradeToAndCall(address(baseImageImpl), "");
        console.log("BaseImageRegistry proxy upgraded:", BASE_IMG);

        UUPSUpgradeable(WORKLOAD).upgradeToAndCall(address(workloadImpl), "");
        console.log("WorkloadRegistry proxy upgraded: ", WORKLOAD);

        UUPSUpgradeable(SESSION_REGISTRY_PROXY).upgradeToAndCall(address(sessionImpl), "");
        console.log("SessionRegistry proxy upgraded:  ", SESSION_REGISTRY_PROXY);

        vm.stopBroadcast();

        // Post-checks (read-only)
        require(
            address(SessionRegistry(SESSION_REGISTRY_PROXY).teeVerifier()) == address(tee), "teeVerifier not rewired"
        );
        console.log("verified teeVerifier()  ->", address(tee));
    }
}
