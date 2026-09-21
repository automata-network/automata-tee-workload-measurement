// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {IDcapAttestationV2} from "../src/interfaces/external/IDcapAttestationV2.sol";
import {IntelTdxDcapV2ZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {ZkProgramConfig, ZkProofType} from "../src/types/Zk.sol";

/// @notice Add the accepted minimal V2 program to the existing Atakit registry.
/// DCAP's owner must register this exact program first. Does not set DCAP defaults.
/// Explicit addresses avoid relying on a deployment file shared by forks and Hoodi.
contract RegisterIntelTdxDcapV2ProgramIdentifier is Script {
    bytes32 internal constant V1_ID = 0x00ed85153a35a84ea1fff62d16ac42f850082f11caea923bf25c20a432bdae46;

    function run() public {
        address owner = vm.envAddress("OWNER");
        ZkVerifierRegistry registry = ZkVerifierRegistry(vm.envAddress("ZK_VERIFIER_REGISTRY_ADDR"));
        IDcapAttestationV2 dcap = IDcapAttestationV2(vm.envAddress("DCAP_V2_ATTESTATION_ADDR"));
        IntelTdxDcapV2ZkVerifierAdapter adapter =
            IntelTdxDcapV2ZkVerifierAdapter(vm.envAddress("INTEL_TDX_DCAP_V2_ADAPTER_ADDR"));
        bytes32 id = vm.envBytes32("INTEL_TDX_DCAP_V2_PROGRAM_IDENTIFIER");
        bytes4 selector = bytes4(vm.envBytes32("DCAP_V2_PROOF_SELECTOR"));
        require(id != bytes32(0) && id != V1_ID, "V2 requires a distinct program ID");
        require(address(adapter).code.length != 0 && address(dcap).code.length != 0, "missing V2 code");
        require(registry.owner() == owner, "registry owner mismatch");
        require(address(adapter.dcapAttestation()) == address(dcap), "adapter DCAP mismatch");
        (bool registered, bool minCheck) = dcap.programModeV2(IDcapAttestationV2.ZkCoProcessorType.Succinct, id);
        require(registered && minCheck && !dcap.zkV2Paused(), "minimal V2 program unavailable");
        require(
            dcap.zkVerifierV2(IDcapAttestationV2.ZkCoProcessorType.Succinct, selector).code.length != 0,
            "proof selector has no verifier"
        );
        ZkProgramConfig memory oldConfig =
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V1_ID);
        require(oldConfig.enabled && oldConfig.verifierAdapter.code.length != 0, "V1 route must remain available");
        ZkProgramConfig memory current =
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, id);
        require(
            current.verifierAdapter == address(0) || current.verifierAdapter == address(adapter),
            "would replace an existing route"
        );

        vm.broadcast(owner);
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, id, address(adapter), true
        );

        require(
            registry.resolveVerifierAdapter(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, id)
                == address(adapter),
            "V2 readback failed"
        );
        require(
            registry.resolveVerifierAdapter(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V1_ID)
                == oldConfig.verifierAdapter,
            "V1 route changed"
        );
        console.log("V2 registered; retained V1 adapter:", oldConfig.verifierAdapter);
    }
}
