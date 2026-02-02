//SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.0;

/**
 * @dev Input structure for attestation report verification
 * Contains the raw attestation data and trusted certificate chain length
 */
struct VerifierInput {
    // Number of trusted certificates in the chain
    uint8 trustedCertsPrefixLen;
    // Raw AWS Nitro Enclave attestation report (COSE_Sign1 format)
    bytes attestationReport;
}

/**
 * @dev Output structure containing verified attestation data and metadata
 * This represents the journal/output from zero-knowledge proof verification
 */
struct VerifierJournal {
    // Overall verification result status
    VerificationResult result;
    // Number of certificates that were trusted during verification
    uint8 trustedCertsPrefixLen;
    // Attestation timestamp (Unix timestamp in milliseconds)
    uint64 timestamp;
    // Array of certificate hashes in the chain (root to leaf)
    bytes32[] certs;
    // User-defined data embedded in the attestation
    bytes userData;
    // Cryptographic nonce used for replay protection
    bytes nonce;
    // Public key extracted from the attestation
    bytes publicKey;
    // Platform Configuration Registers (integrity measurements)
    Pcr[] pcrs;
    // AWS Nitro Enclave module identifier
    string moduleId;
}

/**
 * @dev Public value (journal) structure for batch verification operations
 * Contains the aggregated results of multiple attestation verifications
 */
struct BatchVerifierJournal {
    // Verification key that was used for batch verification
    bytes32 verifierVk;
    // Array of verified attestation results
    VerifierJournal[] outputs;
}

/**
 * @dev 48-byte data structure for storing PCR values
 * Split into two parts due to Solidity's 32-byte word limitation
 */
struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

/**
 * @dev Platform Configuration Register (PCR) entry
 * PCRs contain cryptographic measurements of the enclave's runtime state
 */
struct Pcr {
    // PCR index number (0-23 for AWS Nitro Enclaves)
    uint64 index;
    // 48-byte PCR measurement value (SHA-384 hash)
    Bytes48 value;
}

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

/**
 * @title INitroEnclaveVerifier
 * @dev Interface for AWS Nitro Enclave attestation verification using zero-knowledge proofs
 *
 * This interface defines the contract for verifying AWS Nitro Enclave attestation reports
 * on-chain using zero-knowledge proof systems (RISC Zero or Succinct SP1). The verifier
 * validates the cryptographic integrity of attestation reports while maintaining privacy
 * and reducing gas costs through ZK proofs.
 *
 */
interface INitroEnclaveVerifier {
    /**
     * @dev Enumeration of supported zero-knowledge proof coprocessor types
     * Used to specify which proving system to use for attestation verification
     */
    enum ZkCoProcessorType {
        Unknown,
        // RISC Zero zkVM proving system
        RiscZero,
        // Succinct SP1 proving system
        Succinct
    }

    /**
     * @dev Verifies a single attestation report using zero-knowledge proof
     * @param output Encoded VerifierJournal containing the verification result
     * @param zkCoprocessor Type of ZK coprocessor used to generate the proof
     * @param proofBytes Zero-knowledge proof data for the attestation
     * @return VerifierJournal containing the verification result and extracted data
     *
     * This function:
     * 1. Verifies the ZK proof using the specified coprocessor
     * 2. Decodes the verification result
     * 3. Validates the certificate chain against trusted certificates
     * 4. Checks timestamp validity within the allowed time difference
     * 5. Caches newly discovered trusted certificates
     * 6. Returns the complete verification result
     */
    function verify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal memory);

    /**
     * @dev Verifies multiple attestation reports in a single batch operation
     * @param output Encoded BatchVerifierJournal containing aggregated verification results
     * @param zkCoprocessor Type of ZK coprocessor used to generate the proof
     * @param proofBytes Zero-knowledge proof data for batch verification
     * @return Array of VerifierJournal results, one for each attestation in the batch
     *
     * This function:
     * 1. Verifies the ZK proof using the specified coprocessor
     * 2. Decodes the batch verification results
     * 3. Validates each attestation's certificate chain and timestamp
     * 4. Caches newly discovered trusted certificates
     * 5. Returns the verification results for all attestations
     */
    function batchVerify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal[] memory);
}
