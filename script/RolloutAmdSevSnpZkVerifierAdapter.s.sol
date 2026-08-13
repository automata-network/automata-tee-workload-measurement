// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {ZkProgramConfig, ZkProofType} from "../src/types/Zk.sol";
import {AmdSevSnpZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import "forge-std/console.sol";

interface ISnpAttestationProgramRegistry {
    function programIdentifiers(ISnpAttestation.ZkCoProcessorType zkCoProcessorType)
        external
        view
        returns (bytes32[] memory);
}

/// @title RolloutAmdSevSnpZkVerifierAdapter
/// @notice Deploys only the corrected immutable AMD SEV-SNP adapter and points
///         every accepted Succinct program identifier at it in the existing
///         ZkVerifierRegistry proxy.
/// @dev Required environment:
///      OWNER=<existing ZkVerifierRegistry owner>
///      SNP_ATTESTATION_ADDR=<existing SEVAgentAttestation address>
///      AMD_SEV_SNP_PROGRAM_IDENTIFIERS=<comma-separated accepted identifiers>
///      The target chain's deployment/<chain-id>.json must contain ZkVerifierRegistry.
contract RolloutAmdSevSnpZkVerifierAdapter is DeploymentConfig {
    error NoProgramIdentifiers();
    error ProgramIdentifierCountMismatch(uint256 provided, uint256 accepted);
    error DuplicateProgramIdentifier(bytes32 programIdentifier);
    error ProgramIdentifierNotAccepted(bytes32 programIdentifier);
    error RegistryReadbackMismatch(bytes32 programIdentifier, address expectedAdapter);

    function run() public {
        address owner = vm.envAddress("OWNER");
        address snpAttestationAddress = vm.envAddress("SNP_ATTESTATION_ADDR");
        bytes32[] memory programIdentifiers = vm.envBytes32("AMD_SEV_SNP_PROGRAM_IDENTIFIERS", ",");
        if (programIdentifiers.length == 0) revert NoProgramIdentifiers();

        bytes32[] memory acceptedProgramIdentifiers = ISnpAttestationProgramRegistry(snpAttestationAddress)
            .programIdentifiers(ISnpAttestation.ZkCoProcessorType.Succinct);
        if (programIdentifiers.length != acceptedProgramIdentifiers.length) {
            revert ProgramIdentifierCountMismatch(programIdentifiers.length, acceptedProgramIdentifiers.length);
        }
        for (uint256 i; i < programIdentifiers.length; ++i) {
            for (uint256 j; j < i; ++j) {
                if (programIdentifiers[i] == programIdentifiers[j]) {
                    revert DuplicateProgramIdentifier(programIdentifiers[i]);
                }
            }
            if (!_contains(acceptedProgramIdentifiers, programIdentifiers[i])) {
                revert ProgramIdentifierNotAccepted(programIdentifiers[i]);
            }
        }

        ZkVerifierRegistry registry = ZkVerifierRegistry(readContractAddress("ZkVerifierRegistry"));
        vm.startBroadcast(owner);
        AmdSevSnpZkVerifierAdapter adapter = new AmdSevSnpZkVerifierAdapter(
            ISnpAttestation(snpAttestationAddress), ISnpAttestation.ZkCoProcessorType.Succinct
        );
        for (uint256 i; i < programIdentifiers.length; ++i) {
            registry.setZkProgramConfig(
                ZkProofType.AmdSevSnp, VerificationBackendType.ZkSuccinct, programIdentifiers[i], address(adapter), true
            );
        }
        vm.stopBroadcast();

        for (uint256 i; i < programIdentifiers.length; ++i) {
            ZkProgramConfig memory config = registry.getZkProgramConfig(
                ZkProofType.AmdSevSnp, VerificationBackendType.ZkSuccinct, programIdentifiers[i]
            );
            if (!config.enabled || config.verifierAdapter != address(adapter)) {
                revert RegistryReadbackMismatch(programIdentifiers[i], address(adapter));
            }
        }

        writeToJson("AmdSevSnpZkVerifierAdapter", address(adapter));
        console.log("Corrected AmdSevSnpZkVerifierAdapter deployed at:", address(adapter));
    }

    function _contains(bytes32[] memory identifiers, bytes32 wanted) private pure returns (bool) {
        for (uint256 i; i < identifiers.length; ++i) {
            if (identifiers[i] == wanted) return true;
        }
        return false;
    }
}
