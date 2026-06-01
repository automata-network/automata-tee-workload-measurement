// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ISnpAttestation, VerifierJournal, VerificationResult} from "../interfaces/external/ISnpAttestation.sol";

/// @title MockAutomataSnpAttestation
/// @notice Test double for the AMD SEV-SNP verifier. It parses the SDK's *packed* zkVM public
///         journal exactly as the real SEVAgentAttestation._parseJournal does
///         (amd-sev-snp-attestation-sdk/contracts/src/SEVAgentAttestation.sol), so tests feed the
///         same byte layout the prover emits — in particular reportHash as the trailing 32 bytes.
///         It deliberately skips _verifyJournal's cert/timestamp validation so tests retain control
///         over `result`.
/// @dev Packed layout:
///   u8 result | u64 timestamp (BE) | u8 processorModel | u32 certSize (BE) |
///   bytes32[certSize] certs | uint160[certSize] certSerials (20 bytes each) | bytes32 reportHash
contract MockAutomataSnpAttestation is ISnpAttestation {
    function verifyAndAttestWithZKProof(bytes calldata output, ZkCoProcessorType, bytes calldata)
        external
        pure
        returns (VerifierJournal memory journal)
    {
        uint256 offset = 0;

        journal.result = VerificationResult(uint8(output[offset]));
        offset += 1;

        journal.timestamp = uint64(bytes8(output[offset:offset + 8]));
        offset += 8;

        journal.processorModel = uint8(output[offset]);
        offset += 1;

        uint32 certSize = uint32(bytes4(output[offset:offset + 4]));
        offset += 4;

        journal.certs = new bytes32[](certSize);
        for (uint256 i = 0; i < certSize; i++) {
            journal.certs[i] = bytes32(output[offset:offset + 32]);
            offset += 32;
        }

        journal.certSerials = new uint160[](certSize);
        for (uint256 i = 0; i < certSize; i++) {
            journal.certSerials[i] = uint160(bytes20(output[offset:offset + 20]));
            offset += 20;
        }

        journal.reportHash = bytes32(output[offset:offset + 32]);
    }
}
