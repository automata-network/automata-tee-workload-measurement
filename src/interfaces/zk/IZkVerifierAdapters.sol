// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    AmdSevSnpVerifierJournal,
    AwsNitroTpmJournalV1,
    IntelTdxDcapCompactOutputV1,
    ProgramBoundZkProof,
    TpmQuoteJournalV1
} from "../../types/Zk.sol";

interface IIntelTdxDcapZkVerifierAdapter {
    function verifyProof(ProgramBoundZkProof calldata proof)
        external
        returns (IntelTdxDcapCompactOutputV1 memory compactOutput);
}

interface IAmdSevSnpZkVerifierAdapter {
    function verifyProof(ProgramBoundZkProof calldata proof) external returns (AmdSevSnpVerifierJournal memory journal);
}

interface ITpmQuoteZkVerifierAdapter {
    function verifyProof(ProgramBoundZkProof calldata proof) external view returns (TpmQuoteJournalV1 memory journal);
}

interface IAwsNitroTpmZkVerifierAdapter {
    function verifyProof(ProgramBoundZkProof calldata proof) external view returns (AwsNitroTpmJournalV1 memory journal);
}

/// @notice Minimal Succinct SP1 verifier interface used by direct typed adapters.
interface ISp1Verifier {
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
