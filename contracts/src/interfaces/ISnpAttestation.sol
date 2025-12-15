//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

/// @dev Enumeration of possible attestation verification results.
///      Indicates the outcome of the verification process
enum VerificationResult {
    /// @notice Attestation successfully verified
    Success,
    /// @notice Root certificate is not in the trusted set
    RootCertNotTrusted,
    /// @notice One or more intermediate certificates are not trusted
    IntermediateCertsNotTrusted,
    /// @notice Attestation timestamp is outside acceptable range
    InvalidTimestamp
}

/// @notice Output structure from SNP attestation verification
/// @param result The verification result status
/// @param timestamp Unix timestamp from the attestation report
/// @param processorModel AMD processor model identifier
/// @param rawReport The raw SNP attestation report bytes
/// @param certs Certificate chain hashes used in verification
/// @param certSerials Serial numbers of certificates in the chain
/// @param trustedCertsPrefixLen Number of certificates verified against trusted roots
struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}

/// @title ISnpAttestation
/// @notice Interface for verifying AMD SEV-SNP attestation reports
/// @dev This interface defines the verification of SNP attestation reports using ZK proofs.
/// @custom:security-contact security@ata.network
interface ISnpAttestation {
    /// @notice Type of ZK co-processor used for proof verification
    enum ZkCoProcessorType {
        None,       // No ZK proof (not supported for SNP)
        RiscZero,   // RISC Zero zkVM proof
        Succinct    // Succinct SP1 proof
    }

    /// @notice Verifies an AMD SEV-SNP attestation report with a ZK proof
    /// @dev The ZK proof verifies the SNP report was correctly parsed and validated off-chain,
    ///      allowing for efficient on-chain verification.
    /// @param output The journal/public output from the ZK proof containing parsed report data
    /// @param zkCoprocessor The type of ZK co-processor that generated the proof
    /// @param proofBytes The serialized ZK proof bytes
    /// @return verifiedOutput The verified attestation data including the raw report
    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    )
        external
        returns (VerifierJournal memory verifiedOutput);
}
