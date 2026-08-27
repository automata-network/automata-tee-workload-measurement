// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {VerificationResult} from "../interfaces/external/ISnpAttestation.sol";
import {PcrCommitment} from "./Common.sol";

/// @notice Statement proved by a zero-knowledge program.
enum ZkProofType {
    IntelTdxDcap,
    AmdSevSnp,
    TpmQuote,
    AwsNitroTpm
}

/// @notice Proof data bound to one exact backend program identifier.
struct ProgramBoundZkProof {
    bytes32 programIdentifier;
    bytes output;
    bytes proofBytes;
}

/// @notice Intel TDX proof plus the exact TD10 or TD15 quote body committed by the proof.
struct IntelTdxDcapZkEvidence {
    ProgramBoundZkProof proof;
    bytes quoteBody;
}

/// @notice Compact Atakit output derived from the full Intel TDX DCAP VerifiedOutput.
/// @dev Parsed from the 333-byte ZK journal by IntelTdxDcapZkVerifierAdapter;
///      the journal layout is documented there.
struct IntelTdxDcapCompactOutputV1 {
    uint16 quoteVersion;
    uint16 quoteBodyType;
    uint8 tcbStatus;
    bytes6 fmspc;
    /// @dev Unix timestamp (seconds) committed by the ZK proof in the journal suffix —
    ///      the same bytes the DCAP attestation contract uses for collateral lookups.
    ///      Sourced from the journal rather than the compact output; TeeVerifier enforces
    ///      its freshness.
    uint64 proofTimestamp;
    bytes32 fullQuoteHash;
    bytes32 quoteBodyHash;
    /// @dev keccak256(abi.encode(bytes32("ATKJ_ADVISORY_IDS_V1"), sortedUniqueAdvisoryIds)).
    bytes32 advisoryIdsHash;
}

/// @notice AMD SEV-SNP proof plus the exact report body committed by the proof.
struct AmdSevSnpZkEvidence {
    ProgramBoundZkProof proof;
    bytes rawReport;
}

/// @notice Owner-controlled verifier configuration for one exact proof route.
struct ZkProgramConfig {
    address verifierAdapter;
    bool enabled;
}

/// @notice Typed form of the existing AMD SEV-SNP verifier journal.
struct AmdSevSnpVerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes32 reportHash;
    bytes32[] certs;
    uint160[] certSerials;
}

/// @notice Public result produced by `tpm_quote.v1`.
struct TpmQuoteJournalV1 {
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    bytes32 tpmSignatureHash;
    PcrCommitment pcrCommitment;
    bytes32 policyCommitment;
}

/// @notice Public result produced by `aws_nitrotpm.v1`.
struct AwsNitroTpmJournalV1 {
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    PcrCommitment pcrCommitment;
}
