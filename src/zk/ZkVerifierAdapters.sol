// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IDcapAttestation} from "../interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal} from "../interfaces/external/ISnpAttestation.sol";
import {
    IAmdSevSnpZkVerifierAdapter,
    IAwsNitroTpmZkVerifierAdapter,
    IIntelTdxDcapZkVerifierAdapter,
    ISp1Verifier,
    ITpmQuoteZkVerifierAdapter
} from "../interfaces/zk/IZkVerifierAdapters.sol";
import {
    AmdSevSnpVerifierJournal,
    AwsNitroTpmJournalV1,
    IntelTdxDcapJournalV1,
    ProgramBoundZkProof,
    TpmQuoteJournalV1
} from "../types/Zk.sol";

contract IntelTdxDcapZkVerifierAdapter is IIntelTdxDcapZkVerifierAdapter {
    error DcapProofVerificationFailed(bytes output);
    error InvalidDcapJournalOutputLength(uint256 actual, uint256 expected);

    uint256 private constant INTEL_TDX_DCAP_JOURNAL_OUTPUT_LENGTH = 75;

    IDcapAttestation public immutable dcapAttestation;
    IDcapAttestation.ZkCoProcessorType public immutable zkCoProcessorType;
    uint32 public immutable tcbEvaluationDataNumber;

    constructor(
        IDcapAttestation dcapAttestation_,
        IDcapAttestation.ZkCoProcessorType zkCoProcessorType_,
        uint32 tcbEvaluationDataNumber_
    ) {
        dcapAttestation = dcapAttestation_;
        zkCoProcessorType = zkCoProcessorType_;
        tcbEvaluationDataNumber = tcbEvaluationDataNumber_;
    }

    function verifyProof(ProgramBoundZkProof calldata proof) external returns (IntelTdxDcapJournalV1 memory journal) {
        (bool success, bytes memory output) = dcapAttestation.verifyAndAttestWithZKProof(
            proof.output, zkCoProcessorType, proof.proofBytes, proof.programIdentifier, tcbEvaluationDataNumber
        );
        if (!success) revert DcapProofVerificationFailed(output);
        if (output.length != INTEL_TDX_DCAP_JOURNAL_OUTPUT_LENGTH) {
            revert InvalidDcapJournalOutputLength(output.length, INTEL_TDX_DCAP_JOURNAL_OUTPUT_LENGTH);
        }

        uint16 quoteVersion;
        uint16 quoteBodyType;
        uint8 tcbStatus;
        bytes6 fmspc;
        bytes32 fullQuoteHash;
        bytes32 quoteBodyHash;
        assembly ("memory-safe") {
            let start := add(output, 0x20)
            quoteVersion := shr(240, mload(start))
            quoteBodyType := and(shr(224, mload(start)), 0xffff)
            tcbStatus := byte(4, mload(start))
            fmspc := mload(add(start, 5))
            fullQuoteHash := mload(add(start, 11))
            quoteBodyHash := mload(add(start, 43))
        }
        return IntelTdxDcapJournalV1({
            quoteVersion: quoteVersion,
            quoteBodyType: quoteBodyType,
            tcbStatus: tcbStatus,
            fmspc: fmspc,
            fullQuoteHash: fullQuoteHash,
            quoteBodyHash: quoteBodyHash
        });
    }
}

contract AmdSevSnpZkVerifierAdapter is IAmdSevSnpZkVerifierAdapter {
    ISnpAttestation public immutable snpAttestation;
    ISnpAttestation.ZkCoProcessorType public immutable zkCoProcessorType;

    constructor(ISnpAttestation snpAttestation_, ISnpAttestation.ZkCoProcessorType zkCoProcessorType_) {
        snpAttestation = snpAttestation_;
        zkCoProcessorType = zkCoProcessorType_;
    }

    function verifyProof(ProgramBoundZkProof calldata proof)
        external
        returns (AmdSevSnpVerifierJournal memory journal)
    {
        VerifierJournal memory verified =
            snpAttestation.verifyAndAttestWithZKProof(
                proof.output, zkCoProcessorType, proof.programIdentifier, proof.proofBytes
            );
        return AmdSevSnpVerifierJournal({
            result: verified.result,
            timestamp: verified.timestamp,
            processorModel: verified.processorModel,
            reportHash: verified.reportHash,
            certs: verified.certs,
            certSerials: verified.certSerials
        });
    }
}

abstract contract CanonicalSp1VerifierAdapter {
    error NonCanonicalZkOutput();

    ISp1Verifier public immutable sp1Verifier;

    constructor(ISp1Verifier sp1Verifier_) {
        sp1Verifier = sp1Verifier_;
    }

    function _verify(ProgramBoundZkProof calldata proof) internal view {
        sp1Verifier.verifyProof(proof.programIdentifier, proof.output, proof.proofBytes);
    }

    function _requireCanonical(bytes calldata supplied, bytes memory canonical) internal pure {
        if (supplied.length != canonical.length || keccak256(supplied) != keccak256(canonical)) {
            revert NonCanonicalZkOutput();
        }
    }
}

contract TpmQuoteZkVerifierAdapter is CanonicalSp1VerifierAdapter, ITpmQuoteZkVerifierAdapter {
    constructor(ISp1Verifier sp1Verifier_) CanonicalSp1VerifierAdapter(sp1Verifier_) {}

    function verifyProof(ProgramBoundZkProof calldata proof) external view returns (TpmQuoteJournalV1 memory journal) {
        _verify(proof);
        journal = abi.decode(proof.output, (TpmQuoteJournalV1));
        _requireCanonical(proof.output, abi.encode(journal));
    }
}

contract AwsNitroTpmZkVerifierAdapter is CanonicalSp1VerifierAdapter, IAwsNitroTpmZkVerifierAdapter {
    constructor(ISp1Verifier sp1Verifier_) CanonicalSp1VerifierAdapter(sp1Verifier_) {}

    function verifyProof(ProgramBoundZkProof calldata proof)
        external
        view
        returns (AwsNitroTpmJournalV1 memory journal)
    {
        _verify(proof);
        journal = abi.decode(proof.output, (AwsNitroTpmJournalV1));
        _requireCanonical(proof.output, abi.encode(journal));
    }
}
