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

interface ITpmAttestation is ICertChainRegistry {
    function verifyTpmQuote(
        bytes32 userDataHash,
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        MeasureablePcr[] calldata tpmPcrs,
        bytes[] calldata akCertchain
    ) external returns (bool, string memory);

    function verifyTpmQuote(
        bytes32 userDataHash,
        bytes calldata tpmQuote,
        bytes calldata tpmSignature,
        MeasureablePcr[] calldata tpmPcrs,
        CertPubkey calldata akPub
    ) external view returns (bool, string memory);
}
