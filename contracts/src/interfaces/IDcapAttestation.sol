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

    /// @notice Performs full on-chain verification of a DCAP attestation quote
    /// @param input Serialized attestation input containing the raw quote and any additional
    ///        parameters required by the specific implementation
    /// @return success True if the quote passes all verification checks, false otherwise
    /// @return output On success: serialized verification output containing extracted claims
    ///         (e.g., MRENCLAVE, MRSIGNER, report data, TCB status).
    function verifyAndAttestOnChain(bytes calldata input)
        external
        payable
        returns (bool success, bytes memory output);

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
    /// @return success True if the ZK proof is valid and the attestation passes, false otherwise
    /// @return verifiedOutput The verified attestation output after proof validation,
    ///         containing the same claims as the input output if verification succeeds
    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external payable returns (bool success, bytes memory verifiedOutput);
}
