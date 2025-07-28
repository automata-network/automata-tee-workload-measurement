// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

struct MeasureablePcr {
    // pcr index
    uint256 index;
    // pcr value, must not be zero
    bytes32 pcr;
    // if allEvents.length > 0; extend_sha256(events) = pcr
    bytes32[] allEvents;
    // the index of events wants to measure
    uint256[] measureEventsIdx;
    bool measurePcr;
}

/// PCR Golden Measurement
struct Pcr {
    // pcr index
    uint256 index;
    // sanity check: require(pcr!=0 || measureEvents.length>0)
    // this value is zero if we don't intend to include PCR value as part of the golden measurement
    bytes32 pcr;
    // the subset of events to measure
    bytes32[] measureEvents;
    // the index of events to measure
    uint256[] measureEventsIdx;
}

import {ICertChainRegistry, CertPubkey} from "./ICertChainRegistry.sol";

/**
 * @title Trusted Platform Module (TPM) Onchain Attestation Interface
 * @notice This interface defines the functions for verifying TPM quotes and checking correctness of user data and PCR measurements
 * @notice It extends the ICertChainRegistry to include the ability to configure trusted CA issuers for TPM Attestation Keys
 */
interface ITpmAttestation is ICertChainRegistry {
    /**
     * @notice Verifies a TPM quote
     * @param userDataHash - The hash of the user data
     * @param tpmQuote - The TPM quote to verify
     * @param tpmSignature - The signature of the TPM quote
     * @param tpmPcrs - The PCR measuremnts to validate against the PCR digest in the TPM quote
     * @param akCertchain - The attestation key certificate chain
     * @return success - Whether the verification was successful
     * @return errorMessage - An error message if the verification failed
     */
    function verifyTpmQuote(
        bytes32 userDataHash,
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        MeasureablePcr[] calldata tpmPcrs,
        bytes[] calldata akCertchain
    ) external returns (bool, string memory);

    /**
     * @notice Verifies a TPM quote
     * @dev akPub must be pre-verified before calling this function (saves gas from verifying the entire cert chain)
     * @param userDataHash - The hash of the user data
     * @param tpmQuote - The TPM quote to verify
     * @param tpmSignature - The signature of the TPM quote
     * @param tpmPcrs - The PCR measuremnts to validate against the PCR digest in the TPM quote
     * @param akPub - A pre-verified attestation public key
     * @return success - Whether the verification was successful
     * @return errorMessage - An error message if the verification failed
     */
    function verifyTpmQuote(
        bytes32 userDataHash,
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        MeasureablePcr[] calldata tpmPcrs,
        CertPubkey calldata akPub
    ) external view returns (bool, string memory);
}
