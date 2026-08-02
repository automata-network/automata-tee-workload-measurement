// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {VerificationResult} from "../interfaces/external/ISnpAttestation.sol";

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
    bytes32 sha256PolicyCommitment;
    bytes32 sha384PolicyCommitment;
    bytes32 sha256PcrBindingCommitment;
    bytes32 sha384PcrBindingCommitment;
    bytes32 sha256PcrSetCommitment;
    bytes32 sha384PcrSetCommitment;
}

/// @notice Public result produced by `aws_nitrotpm.v1`.
struct AwsNitroTpmJournalV1 {
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    bytes32 sha384PcrSetCommitment;
}
