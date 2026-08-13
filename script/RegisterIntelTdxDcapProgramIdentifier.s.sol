// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {ZkProgramConfig, ZkProofType} from "../src/types/Zk.sol";
import {IntelTdxDcapZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import "forge-std/console.sol";

interface IDcapAttestationProgramRegistry {
    function programIdentifiers(IDcapAttestation.ZkCoProcessorType zkCoProcessorType)
        external
        view
        returns (bytes32[] memory);
}

/// @title RegisterIntelTdxDcapProgramIdentifier
/// @notice Points one accepted Intel TDX Succinct program identifier at the
///         existing IntelTdxDcapZkVerifierAdapter in the existing
///         ZkVerifierRegistry proxy.
/// @dev This script does not configure AutomataDcapAttestationFee. Its owner
///      must first add INTEL_TDX_DCAP_PROGRAM_IDENTIFIER through
///      setZkConfiguration or updateProgramIdentifier.
///      Required environment:
///      OWNER=<existing ZkVerifierRegistry owner>
///      DCAP_ATTESTATION_ADDR=<existing AutomataDcapAttestationFee address>
///      INTEL_TDX_DCAP_PROGRAM_IDENTIFIER=<accepted identifier>
///      The target chain's deployment/<chain-id>.json must contain
///      ZkVerifierRegistry and IntelTdxDcapZkVerifierAdapter.
contract RegisterIntelTdxDcapProgramIdentifier is DeploymentConfig {
    error ProgramIdentifierNotAccepted(bytes32 programIdentifier);
    error AdapterDcapAttestationMismatch(address actual, address expected);
    error AdapterZkCoProcessorTypeMismatch(
        IDcapAttestation.ZkCoProcessorType actual, IDcapAttestation.ZkCoProcessorType expected
    );
    error RegistryReadbackMismatch(bytes32 programIdentifier, address expectedAdapter);

    function run() public {
        address owner = vm.envAddress("OWNER");
        address dcapAttestationAddress = vm.envAddress("DCAP_ATTESTATION_ADDR");
        bytes32 programIdentifier = vm.envBytes32("INTEL_TDX_DCAP_PROGRAM_IDENTIFIER");

        bytes32[] memory acceptedProgramIdentifiers = IDcapAttestationProgramRegistry(dcapAttestationAddress)
            .programIdentifiers(IDcapAttestation.ZkCoProcessorType.Succinct);
        if (!_contains(acceptedProgramIdentifiers, programIdentifier)) {
            revert ProgramIdentifierNotAccepted(programIdentifier);
        }

        ZkVerifierRegistry registry = ZkVerifierRegistry(readContractAddress("ZkVerifierRegistry"));
        IntelTdxDcapZkVerifierAdapter adapter =
            IntelTdxDcapZkVerifierAdapter(readContractAddress("IntelTdxDcapZkVerifierAdapter"));

        address adapterDcapAttestation = address(adapter.dcapAttestation());
        if (adapterDcapAttestation != dcapAttestationAddress) {
            revert AdapterDcapAttestationMismatch(adapterDcapAttestation, dcapAttestationAddress);
        }
        IDcapAttestation.ZkCoProcessorType adapterZkCoProcessorType = adapter.zkCoProcessorType();
        if (adapterZkCoProcessorType != IDcapAttestation.ZkCoProcessorType.Succinct) {
            revert AdapterZkCoProcessorTypeMismatch(
                adapterZkCoProcessorType, IDcapAttestation.ZkCoProcessorType.Succinct
            );
        }

        vm.broadcast(owner);
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, programIdentifier, address(adapter), true
        );

        ZkProgramConfig memory config = registry.getZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, programIdentifier
        );
        if (!config.enabled || config.verifierAdapter != address(adapter)) {
            revert RegistryReadbackMismatch(programIdentifier, address(adapter));
        }

        console.log("Intel TDX program identifier registered:");
        console.logBytes32(programIdentifier);
        console.log("Existing IntelTdxDcapZkVerifierAdapter:", address(adapter));
    }

    function _contains(bytes32[] memory identifiers, bytes32 wanted) private pure returns (bool) {
        for (uint256 i; i < identifiers.length; ++i) {
            if (identifiers[i] == wanted) return true;
        }
        return false;
    }
}
