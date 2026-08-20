// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {AkCollateralVerifier} from "../src/bases/AkCollateralVerifier.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IMaaKeyRegistry} from "../src/interfaces/registries/IMaaKeyRegistry.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice One-shot Hoodi upgrade: deploy the verified TEE attribute registry
///         implementations, a fresh TeeVerifier, and an ABI-compatible
///         AkCollateralVerifier, then UUPS-upgrade all four existing registry
///         proxies in place.
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
        address amdSnpSecurityPolicyRegistry = vm.envAddress("AMD_SNP_SECURITY_POLICY_REGISTRY");

        AmdSnpSecurityPolicyRegistry amdSnpSecurityPolicyImpl = new AmdSnpSecurityPolicyRegistry();
        console.log("new AmdSnpSecurityPolicyRegistry impl:", address(amdSnpSecurityPolicyImpl));

        BaseImageRegistry baseImageImpl = new BaseImageRegistry(ISignatureVerifier(SIG_VERIFIER));
        console.log("new BaseImageRegistry impl:", address(baseImageImpl));

        WorkloadRegistry workloadImpl = new WorkloadRegistry(ISignatureVerifier(SIG_VERIFIER));
        console.log("new WorkloadRegistry impl: ", address(workloadImpl));

        TeeVerifier tee = new TeeVerifier(
            IDcapAttestation(DCAP),
            ISnpAttestation(SNP),
            vm.envBytes32("TDX_DCAP_PROGRAM_IDENTIFIER"),
            vm.envBytes32("AMD_SEV_SNP_PROGRAM_IDENTIFIER")
        );
        console.log("new TeeVerifier:        ", address(tee));

        // AkCollateralVerificationResult gained the MAA-authenticated TEE type. The old
        // AkCollateralVerifier returns the previous ABI tuple and cannot be decoded by the new
        // SessionRegistry. Preserve its three immutable trust dependencies in a fresh verifier.
        AkCollateralVerifier oldAkCollateralVerifier = AkCollateralVerifier(AK_COLL);
        require(
            address(oldAkCollateralVerifier.signatureVerifier()) == SIG_VERIFIER, "old AK signatureVerifier mismatch"
        );
        require(address(oldAkCollateralVerifier.tpmAttestation()) == TPM, "old AK tpmAttestation mismatch");
        IMaaKeyRegistry maaKeyRegistry = oldAkCollateralVerifier.maaKeyRegistry();
        AkCollateralVerifier akCollateralVerifier =
            new AkCollateralVerifier(maaKeyRegistry, ISignatureVerifier(SIG_VERIFIER), ITpmAttestation(TPM));
        console.log("new AkCollateralVerifier:", address(akCollateralVerifier));

        SessionRegistry sessionImpl = new SessionRegistry(
            ITeeVerifier(address(tee)),
            ITpmAttestation(TPM),
            ISignatureVerifier(SIG_VERIFIER),
            IAkCollateralVerifier(address(akCollateralVerifier)),
            IBaseImageRegistry(BASE_IMG),
            IWorkloadRegistry(WORKLOAD),
            IAmdSnpSecurityPolicyRegistry(amdSnpSecurityPolicyRegistry)
        );
        console.log("new SessionRegistry impl:", address(sessionImpl));

        // Upgrade order matters. AmdSnpSecurityPolicyRegistry MUST go first because
        // VerifiedTeePolicyInputs gained three fields. The new SessionRegistry call would use
        // a selector that the old policy-registry implementation does not expose.
        UUPSUpgradeable(amdSnpSecurityPolicyRegistry).upgradeToAndCall(address(amdSnpSecurityPolicyImpl), "");
        console.log("AmdSnpSecurityPolicyRegistry proxy upgraded:", amdSnpSecurityPolicyRegistry);

        // SessionRegistry MUST go before BaseImageRegistry so the evaluation-time guard
        // (PcrVariantOverridesInvariant) is live before BaseImageRegistry starts rejecting
        // overlapping variants at registration. The reverse order leaves a window in which a
        // variant that pins a profile invariant can still be registered while nothing refuses
        // it at session time. `isSessionActive` does not re-evaluate PCR policy, so a session
        // accepted in that window would stay active until it expires or is revoked.
        //
        // DEPLOYMENT GATE: before running this script, confirm no live hierarchy already has a
        // variant whose overridePcrs index appears in its profile's invariants. Sessions created
        // against such a hierarchy are NOT retroactively invalidated — revoke the affected base
        // image or those sessions first. See docs/verified-tee-attributes-rollout.md.
        UUPSUpgradeable(SESSION_REGISTRY_PROXY).upgradeToAndCall(address(sessionImpl), "");
        console.log("SessionRegistry proxy upgraded:  ", SESSION_REGISTRY_PROXY);

        UUPSUpgradeable(BASE_IMG).upgradeToAndCall(address(baseImageImpl), "");
        console.log("BaseImageRegistry proxy upgraded:", BASE_IMG);

        UUPSUpgradeable(WORKLOAD).upgradeToAndCall(address(workloadImpl), "");
        console.log("WorkloadRegistry proxy upgraded: ", WORKLOAD);

        vm.stopBroadcast();

        // Post-checks (read-only)
        require(
            address(SessionRegistry(SESSION_REGISTRY_PROXY).teeVerifier()) == address(tee), "teeVerifier not rewired"
        );
        console.log("verified teeVerifier()  ->", address(tee));
        require(
            address(SessionRegistry(SESSION_REGISTRY_PROXY).akCollateralVerifier()) == address(akCollateralVerifier),
            "akCollateralVerifier not rewired"
        );
        console.log("verified akCollateralVerifier() ->", address(akCollateralVerifier));
        require(
            address(SessionRegistry(SESSION_REGISTRY_PROXY).amdSnpSecurityPolicyRegistry())
                == amdSnpSecurityPolicyRegistry,
            "amdSnpSecurityPolicyRegistry not rewired"
        );
        console.log("verified amdSnpSecurityPolicyRegistry() ->", amdSnpSecurityPolicyRegistry);
    }
}
