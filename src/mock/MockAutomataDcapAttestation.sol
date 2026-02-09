// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {IDcapAttestation} from "../interfaces/external/IDcapAttestation.sol";

/// @title MockAutomataDcapAttestation
/// @notice Mock DCAP attestation verifier for testing with real TDX quotes
contract MockAutomataDcapAttestation is IDcapAttestation {
    // Quote body sizes
    uint256 private constant TD10_BODY_SIZE = 584;
    uint256 private constant TD15_BODY_SIZE = 648;
    uint256 private constant QUOTE_HEADER_SIZE = 48;

    // Quote body type identifiers
    uint16 private constant QUOTE_BODY_TYPE_TD10 = 2;
    uint16 private constant QUOTE_BODY_TYPE_TD15 = 3;

    function getBp() external pure returns (uint16) {
        return 0;
    }

    function verifyAndAttestOnChain(bytes calldata input) external payable returns (bool, bytes memory) {
        require(input.length >= QUOTE_HEADER_SIZE + TD10_BODY_SIZE, "Input too short");

        // Detect quote body type based on TEE_TCB_SVN2 field at offset 48+8
        // TD15 has additional fields, we can detect by checking if certain bytes are non-zero
        // For simplicity, we check if the quote appears to be TD15 based on structure
        // TD15 has TEE_TCB_SVN2 (16 bytes) and MRSERVICETD (48 bytes) after the TD10 fields

        uint256 bodySize;
        uint16 quoteBodyType;

        // Simple heuristic: check if input is long enough for TD15 and has TD15 marker
        // In practice, TD15 quotes have a different structure after offset 584
        if (input.length >= QUOTE_HEADER_SIZE + TD15_BODY_SIZE) {
            // Check if bytes at TD10 end position look like TD15 extension
            // TD15 has TEE_TCB_SVN2 at offset 48+584 = 632
            bool hasTd15Extension = false;
            for (uint256 i = 0; i < 16; i++) {
                if (input[QUOTE_HEADER_SIZE + TD10_BODY_SIZE + i] != 0) {
                    hasTd15Extension = true;
                    break;
                }
            }
            if (hasTd15Extension) {
                bodySize = TD15_BODY_SIZE;
                quoteBodyType = QUOTE_BODY_TYPE_TD15;
            } else {
                bodySize = TD10_BODY_SIZE;
                quoteBodyType = QUOTE_BODY_TYPE_TD10;
            }
        } else {
            bodySize = TD10_BODY_SIZE;
            quoteBodyType = QUOTE_BODY_TYPE_TD10;
        }

        // Copy quote body from calldata to memory
        bytes memory quoteBody = new bytes(bodySize);
        assembly {
            calldatacopy(add(quoteBody, 32), add(input.offset, QUOTE_HEADER_SIZE), bodySize)
        }

        // Build output: quoteVersion (2) + quoteBodyType (2) + tcbStatus (1) + fmspcBytes (6) + quoteBody
        bytes memory output = abi.encodePacked(
            uint16(4),        // quoteVersion (BE)
            quoteBodyType,    // quoteBodyType (BE)
            uint8(1),         // tcbStatus
            bytes6(0),        // fmspcBytes
            quoteBody
        );

        return (true, output);
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, ZkCoProcessorType, bytes calldata)
        external
        payable
        returns (bool success, bytes memory output)
    {
        uint16 outputLength = uint16(bytes2(journal[0:2]));
        uint256 offset = 2 + outputLength;
        return (true, journal[2:offset]);
    }
}
