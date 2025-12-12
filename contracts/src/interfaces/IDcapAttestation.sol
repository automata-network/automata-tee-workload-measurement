//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

/**
 * @title Interface for DCAP attestation verification with on-chain and ZK proof options
 * @notice Provides two verification methods for attestation input:
 * 1. Full on-chain verification (higher gas cost)
 * 2. ZK proof verification via supported coprocessors (RiscZero, Succinct)
 */
interface IDcapAttestation {
    /**
     * @notice getter for the attestation's base price
     */
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
    function verifyAndAttestOnChain(bytes calldata input)
        external
        payable
        returns (bool success, bytes memory output);

    enum ZkCoProcessorType {
        // if the ZkCoProcessorType is included as None in the AttestationSubmitted event log
        // it indicates that the attestation of the DCAP quote is executed entirely on-chain
        None,
        RiscZero,
        Succinct
    }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external payable returns (bool success, bytes memory verifiedOutput);
}
