//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

/// @title IDcapAttestation
/// @author Automata Network
/// @notice Interface for Intel DCAP quote verification
/// @dev This interface provides two verification methods:
///      1. Full on-chain verification - All verification logic executed on-chain (higher gas cost but trustless)
///      2. ZK proof verification - Offloads heavy computation to ZK coprocessors (lower gas cost)
///      Implementation: https://github.com/automata-network/automata-dcap-attestation
interface IDcapAttestation {
    /// @notice Retrieves the base price (in basis points) for attestation verification
    /// @dev The base price is used to calculate the fee charged for verification services.
    ///      1 basis point = 0.01%, so 100 bp = 1%
    /// @return The base price in basis points
    function getBp() external view returns (uint16);

    /**
     * @notice full on-chain verification for an attestation
     * @dev must further specify the structure of inputs/outputs, to be serialized and passed to this method
     * @param input - serialized raw input as defined by the project
     * @return success - whether the quote has been successfully verified or not
     * @return output - the output upon completion of verification. The output data may require post-processing by the
     * consumer.
     * For verification failures, the output is simply a UTF-8 encoded string, describing the reason for failure.
     * @dev can directly type cast the failed output as a string
     */
    function verifyAndAttestOnChain(bytes calldata input) external payable returns (bool success, bytes memory output);

    /// @notice Enumeration of supported Zero-Knowledge coprocessor types
    /// @dev ZK coprocessors offload expensive verification computations off-chain
    ///      while maintaining cryptographic guarantees through validity proofs
    enum ZkCoProcessorType {
        /// @notice No ZK coprocessor used - indicates full on-chain verification
        None,
        /// @notice RiscZero zkVM coprocessor
        /// @dev Proofs are verified using the RiscZero verifier contract.
        RiscZero,
        /// @notice Succinct SP1 coprocessor
        /// @dev Proofs are verified using the Succinct verifier contract.
        Succinct
    }

    /// @notice Verifies a DCAP attestation using a pre-generated ZK proof
    /// @param output The verification output/public inputs from the ZK circuit execution,
    ///        containing the attestation claims to be verified
    /// @param zkCoprocessor The type of ZK coprocessor that generated the proof,
    ///        determining which verifier contract to use
    /// @param proofBytes The serialized ZK proof bytes in the format expected by
    ///        the corresponding verifier (RiscZero or Succinct)
    /// @param programIdentifier The exact ZK guest program identifier that generated the proof
    /// @param tcbEvaluationDataNumber The Intel TCB collateral version used to build the proof
    /// @return success True if the ZK proof is valid and the attestation passes, false otherwise
    /// @return verifiedOutput The verified attestation output after proof validation,
    ///         containing the same claims as the input output if verification succeeds
    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes,
        bytes32 programIdentifier,
        uint32 tcbEvaluationDataNumber
    ) external payable returns (bool success, bytes memory verifiedOutput);
}
