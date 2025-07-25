// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {Bytes48, LibBytes} from "./LibBytes.sol";
import {CertPubkey, LibX509} from "./LibX509.sol";
import {ICertChainRegistry} from "../interfaces/ICertChainRegistry.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibString} from "@solady/utils/LibString.sol";

using LibTPM for WorkloadCollaterals global;
using LibTPM for MeasureablePcr global;
using LibTPM for Pcr global;

using LibString for string;
using LibBytes for bytes;

struct Pcr {
    // pcr index
    uint256 index;
    // sanity check: require(pcr!=0 || measureEvents.length>0)
    // set to zero if no need to measure the pcr value
    bytes32 pcr;
    // the events wants to measure
    bytes32[] measureEvents;
    uint256[] measureEventsIdx;
}

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

struct WorkloadCollaterals {
    // verified by tpmSignature
    bytes tpmQuote;
    bytes tpmSignature;
    // verified by tpmQuote
    MeasureablePcr[] pcrs;
    // tdx&gcp: uuid
    bytes reportId;
    // gcp: akPub
    // azure: varDataJson
    bytes akPub;
    // gcp: certs
    // azure: empty
    bytes[] certs;
}

library LibTPM {
    uint16 internal constant HASH_RSA = 0x000B;
    uint16 internal constant SIG_RSA = 0x0014;
    uint16 internal constant SIG_ECDSA = 0x0018;

    function verifyTpmQuote(
        WorkloadCollaterals calldata _workload,
        CertPubkey memory verifiedAkPub,
        address certChainRegistryAddr
    ) internal view {
        uint16 sigAlg;
        uint16 hashAlg;
        uint16 sigSize;
        bytes memory tpmSignature = _workload.tpmSignature;
        assembly {
            let offset := add(tpmSignature, 0x20)
            sigAlg := shr(240, mload(offset))
            offset := add(offset, 2)

            hashAlg := shr(240, mload(offset))
            offset := add(offset, 2)

            sigSize := shr(240, mload(offset))
            offset := add(offset, 2)
        }

        require(hashAlg == HASH_RSA, "hashAlg != RSA");
        bytes memory sig;
        if (sigAlg == SIG_RSA) {
            sig = _workload.tpmSignature.slice(6, sigSize);
        } else if (sigAlg == SIG_ECDSA) {
            require(sigSize == 32, "invalid r size");
            sig = new bytes(64);
            uint16 sSize;
            assembly {
                let offset := add(tpmSignature, 0x20)
                mstore(add(sig, 0x20), mload(add(offset, 6)))
                sSize := shr(240, mload(add(offset, 38)))
                mstore(add(sig, 0x40), mload(add(offset, 40)))
            }
            require(sSize == 32, "invalid s size");
        } else {
            revert("unknown sigAlg");
        }

        bytes32 message = sha256(_workload.tpmQuote);
        bool result = ICertChainRegistry(certChainRegistryAddr).verifySignature(message, sig, verifiedAkPub);
        require(result, "tpm quote verification failed(RSA)");
    }

    function verifyAkPub(bytes[] calldata certs, address certChainRegistry) internal returns (CertPubkey memory) {
        return ICertChainRegistry(certChainRegistry).verifyCertChain(certs);
    }

    function verifyPcrs(MeasureablePcr[] calldata pcrs, bytes memory quote) internal pure {
        // Quote Layout:
        // =====================================
        // magic: [0..4]
        // att_type: [4..6]
        // qualified_signer_len: [6..8]
        // qualified_signer: [8..8+qualified_signer_len]
        // extra_data_len: [8+qualified_signer_len..10+qualified_signer_len]
        // extra_data: [10+qualified_signer_len..10+qualified_signer_len+extra_data_len]
        // clock_info: [10+qualified_signer_len+extra_data_len..10+qualified_signer_len+extra_data_len+17]
        // firmware_version: [27+qualified_signer_len+extra_data_len..27+qualified_signer_len+extra_data_len+8]
        // if att_type == 0x8018
        //   parse TPMSQuoteInfo
        //   count: [35+qualified_signer_len+extra_data_len..35+qualified_signer_len+extra_data_len+4]
        //   assert count == 1:
        //   pcr_selections: TPMSPCRSelection[0]:
        //     hash: [39+qualified_signer_len+extra_data_len + ..39+qualified_signer_len+extra_data_len+2]
        //     pcr_size: [41+qualified_signer_len+extra_data_len + ..41+qualified_signer_len+extra_data_len+1]
        //     pcrs: [42+qualified_signer_len+extra_data_len + ..42+qualified_signer_len+extra_data_len+pcr_size]
        //   pcr_digest_size:
        // [42+qualified_signer_len+extra_data_len+pcr_size..42+qualified_signer_len+extra_data_len+pcr_size+2]
        //   pcr_digest:
        // [44+qualified_signer_len+extra_data_len+pcr_size..44+qualified_signer_len+extra_data_len+pcr_size+pcr_digest_size]
        // END

        uint16 attType;
        uint16 qualifiedSignerLen;
        uint16 extraDataLen;
        uint32 tpmsPCRCount;
        uint8 pcrSize0;
        uint16 pcrDigestLen;
        bytes32 pcrDigest;
        bytes4 pcrSelection;
        assembly {
            let offset := add(quote, add(0x20, 4))
            attType := shr(240, mload(offset)) // [4..6]
            offset := add(offset, 2)

            qualifiedSignerLen := shr(240, mload(offset))
            offset := add(offset, add(2, qualifiedSignerLen)) // len + qualifiedSigner

            extraDataLen := shr(240, mload(offset)) //
            offset := add(offset, add(2, extraDataLen))
            // len + extraData

            // clock_info: 17
            // firmware_version: 8
            offset := add(offset, 25)
            tpmsPCRCount := shr(224, mload(offset))
            offset := add(offset, 4)
            // assert tpmsPCRCount == 1

            // hash: 2
            offset := add(offset, 2)

            pcrSize0 := shr(248, mload(offset))
            offset := add(offset, 1)

            pcrSelection := mload(offset)
            offset := add(offset, pcrSize0)

            pcrDigestLen := shr(240, mload(offset))
            pcrDigest := mload(add(offset, 2))
        }

        // TODO: mask pcrSelection

        require(attType == 0x8018, "attType != 0x8018");
        require(tpmsPCRCount == 1, "tpmsPCRCount != 1");
        require(pcrDigestLen == 32, "pcrDigestLen != 32");
        bytes4 selection = LibTPM.compactSelections(pcrs);
        require(selection == pcrSelection, "pcrSelection != pcrs.compactSelections()");
        require(LibTPM.digest(pcrs) == pcrDigest, "pcrs.hash() != pcrDigest");
    }

    function quoteExtraData(bytes memory tpmQuote) internal pure returns (bytes32) {
        uint16 extraDataLen;
        uint16 qualifiedSignerLen;
        uint256 offset;
        bytes32 extraData;
        assembly {
            offset := add(tpmQuote, add(0x20, 4))
            offset := add(offset, 2) // attType
            qualifiedSignerLen := shr(240, mload(offset))
            offset := add(offset, add(2, qualifiedSignerLen)) // len + qualifiedSigner
            extraDataLen := shr(240, mload(offset))
            extraData := mload(add(offset, 2))
        }
        require(extraDataLen == 32, "extraDataLen != 32");
        return extraData;
    }

    function varDataPubkey(string memory data) internal pure returns (CertPubkey memory) {
        uint256 off = 0;
        uint256 pos;
        pos = data.indexOf("\"kid\":\"HCLAkPub\"", off);
        if (pos == type(uint256).max) {
            revert("not found");
        }
        off = pos + 16;

        string memory kty;
        {
            pos = data.indexOf("\"kty\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid kty");
            }
            off = pos + 7;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid kty");
            }
            kty = data.slice(off, pos);
            require(kty.eq("RSA"), "invalid kty");
            off = pos + 1;
        }

        // e
        string memory eBase64;
        {
            pos = data.indexOf("\"e\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid e");
            }
            off = pos + 5;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid e");
            }
            eBase64 = data.slice(off, pos);
            off = pos + 1;
        }

        // n
        string memory nBase64;
        {
            pos = data.indexOf("\"n\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid n");
            }
            off = pos + 5;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid n");
            }
            nBase64 = data.slice(off, pos);
            off = pos + 1;
        }

        pos = data.indexOf("\"kid\":\"HCLEkPub\"", off);
        if (pos == type(uint256).max) {
            revert("data mixed up");
        }

        return LibX509.newRsaPubkey(Base64.decode(eBase64), Base64.decode(nBase64));
    }

    function compactSelections(MeasureablePcr[] calldata mpcrs) internal pure returns (bytes4) {
        // Use a single uint32 instead of an array to reduce memory operations
        uint32 bitmap;
        uint256 len = mpcrs.length;

        // Cache array length and use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < len && i < 32; i++) {
                uint256 idx = mpcrs[i].index;
                // Set bit directly in the bitmap using a single operation
                bitmap |= uint32(1 << idx);
            }
        }

        // Convert to bytes4 in a single operation
        return bytes4(
            ((bitmap & 0xFF000000) >> 24) | ((bitmap & 0x00FF0000) >> 8) | ((bitmap & 0x0000FF00) << 8)
                | ((bitmap & 0x000000FF) << 24)
        );
    }

    function digest(MeasureablePcr[] calldata mpcrs) internal pure returns (bytes32) {
        bytes memory concatenated;

        for (uint256 i = 0; i < mpcrs.length; i++) {
            concatenated = abi.encodePacked(concatenated, mpcrs[i].pcr);
        }

        return sha256(concatenated);
    }

    function toPcr(MeasureablePcr[] calldata mpcrs) internal pure returns (Pcr[] memory) {
        // Cache array length to avoid multiple storage reads
        uint256 mpcrsLength = mpcrs.length;
        Pcr[] memory pcrs = new Pcr[](mpcrsLength);

        // Use unchecked to save gas on bounds checking where we know it's safe
        unchecked {
            for (uint256 i = 0; i < mpcrsLength; i++) {
                // Cache the current MeasureablePcr to avoid multiple calldata accesses
                MeasureablePcr calldata currentMpcr = mpcrs[i];

                // Verify events before allocating memory for arrays
                require(verifyEvents(currentMpcr), "Invalid all events");

                // Cache the measureEventsIdx length
                uint256 eventsIdxLength = currentMpcr.measureEventsIdx.length;

                // Only allocate memory if there are events to process
                bytes32[] memory measureEvents = new bytes32[](eventsIdxLength);
                uint256[] memory measureEventsIdx = new uint256[](eventsIdxLength);

                // Process events only if there are any
                if (eventsIdxLength > 0) {
                    uint256 allEventsLength = currentMpcr.allEvents.length;

                    for (uint256 j = 0; j < eventsIdxLength; j++) {
                        uint256 eventIdx = currentMpcr.measureEventsIdx[j];
                        require(eventIdx < allEventsLength, "Invalid event index");
                        measureEvents[j] = currentMpcr.allEvents[eventIdx];
                        measureEventsIdx[j] = eventIdx;
                    }
                }

                // Create the PCR with the correct values
                pcrs[i] = Pcr({
                    index: currentMpcr.index,
                    pcr: currentMpcr.measurePcr ? currentMpcr.pcr : bytes32(0),
                    measureEvents: measureEvents,
                    measureEventsIdx: measureEventsIdx
                });
            }
        }
        return pcrs;
    }

    function verifyEvents(MeasureablePcr calldata mpcr) internal pure returns (bool) {
        // Early return conditions
        if (mpcr.pcr == bytes32(0)) {
            return true;
        }

        uint256 allEventsLength = mpcr.allEvents.length;
        if (allEventsLength == 0) {
            return true;
        }

        bytes32 before = bytes32(0);
        // Use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < allEventsLength; i++) {
                before = sha256(abi.encodePacked(before, mpcr.allEvents[i]));
            }
        }

        return before == mpcr.pcr;
    }

    function toString(Pcr memory pcr) internal pure returns (string memory) {
        return
            string(abi.encodePacked("{index:", LibBytes.toString(pcr.index), ",pcr:", LibBytes.toString(pcr.pcr), "}"));
    }
}
