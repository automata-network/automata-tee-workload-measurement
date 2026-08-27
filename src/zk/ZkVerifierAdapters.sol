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
    IntelTdxDcapCompactOutputV1,
    ProgramBoundZkProof,
    TpmQuoteJournalV1
} from "../types/Zk.sol";

contract IntelTdxDcapZkVerifierAdapter is IIntelTdxDcapZkVerifierAdapter {
    error DcapProofVerificationFailed(bytes output);
    error InvalidDcapCompactOutputLength(uint256 actual, uint256 expected);
    error InvalidDcapCompactOutputFormatGuard(bytes16 actual);
    error InvalidDcapCompactOutputMagic(bytes4 actual);
    error UnsupportedDcapCompactOutputType(uint16 actual);
    error UnsupportedDcapCompactOutputVersion(uint16 actual);

    /// @dev Intel TDX DCAP ZK journal layout (333 bytes, committed by the guest program
    ///      and bound to the verified proof). All offsets below are journal-absolute:
    ///
    ///      offset  len   content
    ///      0       2     big-endian compact output length (= 131)
    ///      2       131   compact output:
    ///                    2..13    quoteVersion(2) | quoteBodyType(2) | tcbStatus(1) | fmspc(6)
    ///                    13..29   format guard (all zero)
    ///                    29..33   "ATKJ" magic
    ///                    33..35   format type (= 1)
    ///                    35..37   format version (= 1)
    ///                    37..69   fullQuoteHash
    ///                    69..101  quoteBodyHash
    ///                    101..133 advisoryIdsHash
    ///      133     8     big-endian proof-committed timestamp (Unix seconds)
    ///      141     192   collateral hashes, 32 bytes each: TCB info, QE identity,
    ///                    Root CA cert, TCB signing cert, Root CRL, PCK CRL
    ///
    ///      The DCAP attestation contract verifies the collateral hashes against
    ///      on-chain PCCS state at the committed timestamp, then returns only the
    ///      compact output; the timestamp is read from the journal directly.
    ///      Mirrored in crates/automata-tee-workload-measurement/src/session_registry.rs
    ///      — keep the two copies in sync.
    uint256 private constant INTEL_TDX_DCAP_COMPACT_OUTPUT_V1_LENGTH = 131;
    bytes4 private constant INTEL_TDX_DCAP_COMPACT_OUTPUT_MAGIC = 0x41544b4a; // "ATKJ"
    uint16 private constant INTEL_TDX_DCAP_COMPACT_OUTPUT_TYPE = 1;
    uint16 private constant INTEL_TDX_DCAP_COMPACT_OUTPUT_VERSION = 1;

    /// @dev Offset of the proof-committed timestamp inside the full ZK journal:
    ///      two-byte length prefix + 131-byte compact output. These are the same
    ///      eight bytes the DCAP attestation contract uses for collateral lookups.
    uint256 private constant INTEL_TDX_DCAP_JOURNAL_TIMESTAMP_OFFSET = 2 + INTEL_TDX_DCAP_COMPACT_OUTPUT_V1_LENGTH;

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

    function verifyProof(ProgramBoundZkProof calldata proof)
        external
        returns (IntelTdxDcapCompactOutputV1 memory compactOutput)
    {
        (bool success, bytes memory output) = dcapAttestation.verifyAndAttestWithZKProof(
            proof.output, zkCoProcessorType, proof.proofBytes, proof.programIdentifier, tcbEvaluationDataNumber
        );
        if (!success) revert DcapProofVerificationFailed(output);
        if (output.length != INTEL_TDX_DCAP_COMPACT_OUTPUT_V1_LENGTH) {
            revert InvalidDcapCompactOutputLength(output.length, INTEL_TDX_DCAP_COMPACT_OUTPUT_V1_LENGTH);
        }

        uint16 quoteVersion;
        uint16 quoteBodyType;
        uint8 tcbStatus;
        bytes6 fmspc;
        bytes16 formatGuard;
        bytes4 magic;
        uint16 formatType;
        uint16 formatVersion;
        bytes32 fullQuoteHash;
        bytes32 quoteBodyHash;
        bytes32 advisoryIdsHash;
        assembly ("memory-safe") {
            let start := add(output, 0x20)
            quoteVersion := shr(240, mload(start))
            quoteBodyType := and(shr(224, mload(start)), 0xffff)
            tcbStatus := byte(4, mload(start))
            fmspc := mload(add(start, 5))
            formatGuard := mload(add(start, 11))
            magic := mload(add(start, 27))
            formatType := shr(240, mload(add(start, 31)))
            formatVersion := shr(240, mload(add(start, 33)))
            fullQuoteHash := mload(add(start, 35))
            quoteBodyHash := mload(add(start, 67))
            advisoryIdsHash := mload(add(start, 99))
        }
        if (formatGuard != bytes16(0)) {
            revert InvalidDcapCompactOutputFormatGuard(formatGuard);
        }
        if (magic != INTEL_TDX_DCAP_COMPACT_OUTPUT_MAGIC) {
            revert InvalidDcapCompactOutputMagic(magic);
        }
        if (formatType != INTEL_TDX_DCAP_COMPACT_OUTPUT_TYPE) {
            revert UnsupportedDcapCompactOutputType(formatType);
        }
        if (formatVersion != INTEL_TDX_DCAP_COMPACT_OUTPUT_VERSION) {
            revert UnsupportedDcapCompactOutputVersion(formatVersion);
        }
        // The proof-committed timestamp immediately follows the compact output in the
        // ZK journal — the same eight bytes the DCAP attestation contract uses for its
        // collateral lookups. The journal is bound to the verified proof, so the
        // timestamp cannot be forged without invalidating the proof.
        uint64 proofTimestamp = uint64(
            bytes8(proof.output[INTEL_TDX_DCAP_JOURNAL_TIMESTAMP_OFFSET:INTEL_TDX_DCAP_JOURNAL_TIMESTAMP_OFFSET + 8])
        );
        return IntelTdxDcapCompactOutputV1({
            quoteVersion: quoteVersion,
            quoteBodyType: quoteBodyType,
            tcbStatus: tcbStatus,
            fmspc: fmspc,
            proofTimestamp: proofTimestamp,
            fullQuoteHash: fullQuoteHash,
            quoteBodyHash: quoteBodyHash,
            advisoryIdsHash: advisoryIdsHash
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
