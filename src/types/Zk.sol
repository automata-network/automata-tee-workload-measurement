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

/// @notice Intel TDX proof plus the exact TD10 or TD15 quote body committed by the proof.
struct IntelTdxDcapZkEvidence {
    ProgramBoundZkProof proof;
    bytes quoteBody;
}

/// @notice Verified compact result produced by `intel_tdx_dcap.v1`.
struct IntelTdxDcapJournalV1 {
    uint16 quoteVersion;
    uint16 quoteBodyType;
    uint8 tcbStatus;
    bytes6 fmspc;
    bytes32 fullQuoteHash;
    bytes32 quoteBodyHash;
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
    bytes32 pcrDigest;
    bytes32 verificationRequestCommitment;
}

/// @notice Public result produced by `aws_nitrotpm.v1`.
struct AwsNitroTpmJournalV1 {
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    bytes32 pcrDigest;
    bytes32 verificationRequestCommitment;
}
