// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {IDcapAttestationV2} from "../src/interfaces/external/IDcapAttestationV2.sol";
import {IntelTdxDcapV2ZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {ZkProgramConfig, ZkProofType} from "../src/types/Zk.sol";

/// @notice Run without --broadcast first. Preserves the proxy, its storage,
/// all non-TEE dependencies, and the exact existing V1 program route.
contract UpgradeDcapV2 is Script {
    bytes32 internal constant V1_ID = 0x00ed85153a35a84ea1fff62d16ac42f850082f11caea923bf25c20a432bdae46;
    bytes32 internal constant V2_ID = 0x00c8b2488a43ef337639997a56c160087126c97fec1667c0e2ecbe137688729f;
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function run() public {
        require(block.chainid == vm.envUint("EXPECTED_CHAIN_ID"), "unexpected chain");
        address owner = vm.envAddress("OWNER");
        SessionRegistry session = SessionRegistry(vm.envAddress("SESSION_REGISTRY_ADDR"));
        address oldImplementation = address(uint160(uint256(vm.load(address(session), IMPLEMENTATION_SLOT))));
        require(oldImplementation == vm.envAddress("EXPECTED_SESSION_IMPLEMENTATION"), "implementation changed");
        require(session.owner() == owner, "session owner mismatch");
        TeeVerifier oldTee = TeeVerifier(address(session.teeVerifier()));
        ZkVerifierRegistry registry = ZkVerifierRegistry(address(oldTee.zkVerifierRegistry()));
        require(registry.owner() == owner, "program registry owner mismatch");
        ZkProgramConfig memory v1 =
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V1_ID);
        require(v1.enabled && v1.verifierAdapter.code.length != 0, "V1 route unavailable");
        ZkProgramConfig memory v2 =
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V2_ID);
        require(v2.verifierAdapter == address(0), "V2 route already exists; review before replacing");
        IDcapAttestationV2 dcap = IDcapAttestationV2(vm.envAddress("DCAP_V2_ATTESTATION_ADDR"));
        (bool registered, bool minimal) = dcap.programModeV2(IDcapAttestationV2.ZkCoProcessorType.Succinct, V2_ID);
        require(registered && minimal && !dcap.zkV2Paused(), "minimal V2 unavailable");
        bytes4 selector = bytes4(vm.envBytes32("DCAP_V2_PROOF_SELECTOR"));
        require(
            dcap.zkVerifierV2(IDcapAttestationV2.ZkCoProcessorType.Succinct, selector).code.length != 0,
            "V2 proof verifier unavailable"
        );

        vm.startBroadcast(owner);
        IntelTdxDcapV2ZkVerifierAdapter adapter = new IntelTdxDcapV2ZkVerifierAdapter(dcap);
        TeeVerifier tee = new TeeVerifier(dcap, oldTee.zkVerifierRegistry());
        SessionRegistry implementation = new SessionRegistry(
            ITeeVerifier(address(tee)),
            session.tpmVerifier(),
            session.signatureVerifier(),
            session.akCollateralVerifier(),
            session.baseImageRegistry(),
            session.workloadRegistry(),
            session.teeSecurityPolicyVerifier()
        );
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V2_ID, address(adapter), true
        );
        session.upgradeToAndCall(address(implementation), "");
        vm.stopBroadcast();

        require(address(session.teeVerifier()) == address(tee), "TEE switch failed");
        require(
            registry.resolveVerifierAdapter(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V1_ID)
                == v1.verifierAdapter,
            "V1 route changed"
        );
        console.log("Session proxy", address(session));
        console.log("Previous implementation (rollback)", oldImplementation);
        console.log("New implementation", address(implementation));
        console.log("New TeeVerifier", address(tee));
        console.log("New V2 adapter", address(adapter));
    }
}
