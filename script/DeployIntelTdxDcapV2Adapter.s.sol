// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {IDcapAttestationV2} from "../src/interfaces/external/IDcapAttestationV2.sol";
import {IntelTdxDcapV2ZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";

/// @notice Deploy only the V2 adapter. Existing V1 contracts and registrations are untouched.
contract DeployIntelTdxDcapV2Adapter is DeploymentConfig {
    function run() public {
        address dcap = vm.envAddress("DCAP_V2_ATTESTATION_ADDR");
        require(dcap.code.length != 0, "DCAP V2 has no code");
        // This selector is absent from the old FeeV2 contract.
        IDcapAttestationV2(dcap).programModeV2(IDcapAttestationV2.ZkCoProcessorType.Succinct, bytes32(0));
        vm.broadcast(vm.envAddress("OWNER"));
        IntelTdxDcapV2ZkVerifierAdapter adapter =
            new IntelTdxDcapV2ZkVerifierAdapter{salt: keccak256("INTEL_TDX_DCAP_V2_ADAPTER")}(IDcapAttestationV2(dcap));
        writeToJson("IntelTdxDcapV2ZkVerifierAdapter", address(adapter));
    }
}
