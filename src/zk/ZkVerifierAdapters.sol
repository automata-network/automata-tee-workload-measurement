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
import {AmdSevSnpVerifierJournal, AwsNitroTpmJournalV1, ProgramBoundZkProof, TpmQuoteJournalV1} from "../types/Zk.sol";

contract IntelTdxDcapZkVerifierAdapter is IIntelTdxDcapZkVerifierAdapter {
    error DcapProofVerificationFailed(bytes output);

    IDcapAttestation public immutable dcapAttestation;
    IDcapAttestation.ZkCoProcessorType public immutable zkCoProcessorType;

    constructor(IDcapAttestation dcapAttestation_, IDcapAttestation.ZkCoProcessorType zkCoProcessorType_) {
        dcapAttestation = dcapAttestation_;
        zkCoProcessorType = zkCoProcessorType_;
    }

    function verifyProof(ProgramBoundZkProof calldata proof) external returns (bytes memory verifiedDcapOutput) {
        (bool success, bytes memory output) =
            dcapAttestation.verifyAndAttestWithZKProof(proof.output, zkCoProcessorType, proof.proofBytes);
        if (!success) revert DcapProofVerificationFailed(output);
        return output;
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
            snpAttestation.verifyAndAttestWithZKProof(proof.output, zkCoProcessorType, proof.proofBytes);
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
