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
    uint16 private constant QUOTE_BODY_TYPE_SGX = 1;
    uint16 private constant QUOTE_BODY_TYPE_TD10 = 2;
    uint16 private constant QUOTE_BODY_TYPE_TD15 = 3;

    // V5 body header: u16 bodyType + u32 size
    uint256 private constant V5_BODY_HEADER_SIZE = 6;

    function getBp() external pure returns (uint16) {
        return 0;
    }

    function verifyAndAttestOnChain(bytes calldata input) external payable returns (bool, bytes memory) {
        require(input.length >= QUOTE_HEADER_SIZE + TD10_BODY_SIZE, "Input too short");

        // Read quote version (LE uint16 from input[0:2])
        uint16 quoteVersion = uint16(uint8(input[0])) | (uint16(uint8(input[1])) << 8);
        require(quoteVersion == 4 || quoteVersion == 5, "Unsupported quote version");

        // Reject SGX tee_type (input[4:8] == all zeros means SGX)
        require(input[4] != 0 || input[5] != 0 || input[6] != 0 || input[7] != 0, "SGX quotes not supported");

        uint256 bodySize;
        uint16 quoteBodyType;
        uint256 bodyOffset;

        if (quoteVersion == 4) {
            // V4: body is always TD10, starts right after the 48-byte header
            bodySize = TD10_BODY_SIZE;
            quoteBodyType = QUOTE_BODY_TYPE_TD10;
            bodyOffset = QUOTE_HEADER_SIZE;
        } else {
            // V5: read body header at input[48:54]
            // u16 bodyType (LE) at input[48:50]
            uint16 bodyType = uint16(uint8(input[48])) | (uint16(uint8(input[49])) << 8);
            // u32 size (LE) at input[50:54]
            uint32 declaredSize = uint32(uint8(input[50])) | (uint32(uint8(input[51])) << 8)
                | (uint32(uint8(input[52])) << 16) | (uint32(uint8(input[53])) << 24);

            require(bodyType != QUOTE_BODY_TYPE_SGX, "SGX body type not supported");

            if (bodyType == QUOTE_BODY_TYPE_TD10) {
                bodySize = TD10_BODY_SIZE;
            } else if (bodyType == QUOTE_BODY_TYPE_TD15) {
                bodySize = TD15_BODY_SIZE;
            } else {
                revert("Unsupported body type");
            }

            require(declaredSize == bodySize, "Body size mismatch");

            quoteBodyType = bodyType;
            bodyOffset = QUOTE_HEADER_SIZE + V5_BODY_HEADER_SIZE;

            require(input.length >= bodyOffset + bodySize, "Input too short for V5 body");
        }

        // Copy quote body from calldata to memory
        bytes memory quoteBody = new bytes(bodySize);
        assembly {
            calldatacopy(add(quoteBody, 32), add(input.offset, bodyOffset), bodySize)
        }

        // Build output: quoteVersion (2) + quoteBodyType (2) + tcbStatus (1) + fmspcBytes (6) + quoteBody
        bytes memory output = abi.encodePacked(
            quoteVersion, // actual version (BE)
            quoteBodyType, // quoteBodyType (BE)
            uint8(1), // tcbStatus
            bytes6(0), // fmspcBytes
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
