//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

/**
 * @dev Enumeration of possible attestation verification results
 * Indicates the outcome of the verification process
 */
enum VerificationResult {
    // Attestation successfully verified
    Success,
    // Root certificate is not in the trusted set
    RootCertNotTrusted,
    // One or more intermediate certificates are not trusted
    IntermediateCertsNotTrusted,
    // Attestation timestamp is outside acceptable range
    InvalidTimestamp
}

struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}

interface ISnpAttestation {
    enum ZkCoProcessorType {
        None,
        RiscZero,
        Succinct
    }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory verifiedOutput);
}
