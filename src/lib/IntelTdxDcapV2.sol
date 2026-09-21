// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OutputV2} from "./dcap-v2/OutputV2.sol";
import {OutputV2Codec} from "./dcap-v2/OutputV2Codec.sol";
import {IntelTdxDcapCompactOutputV1} from "../types/Zk.sol";

/// @notice Decode already authenticated DCAP output into Atakit's internal fields.
library IntelTdxDcapV2 {
    error UnsupportedTdxQuote(uint16 version, uint16 bodyType);

    function decode(bytes memory output) internal pure returns (IntelTdxDcapCompactOutputV1 memory) {
        OutputV2 memory out = OutputV2Codec.decode(output);
        if (!((out.quoteVersion == 4 && out.quoteBodyType == 2)
                    || (out.quoteVersion == 5 && (out.quoteBodyType == 2 || out.quoteBodyType == 3)))) {
            revert UnsupportedTdxQuote(out.quoteVersion, out.quoteBodyType);
        }
        return IntelTdxDcapCompactOutputV1({
            quoteVersion: out.quoteVersion,
            quoteBodyType: out.quoteBodyType,
            tcbStatus: out.tcbStatus,
            fmspc: out.fmspc,
            fullQuoteHash: out.fullQuoteHash,
            quoteBodyHash: out.quoteBodyHash,
            advisoryIdsHash: advisoryIdsHash(out.advisoryIDs)
        });
    }

    /// @dev Match Rust: sort UTF-8 bytes, deduplicate, ABI-encode domain and IDs.
    function advisoryIdsHash(string[] memory ids) internal pure returns (bytes32) {
        for (uint256 i = 1; i < ids.length; ++i) {
            string memory value = ids[i];
            uint256 j = i;
            while (j > 0 && _less(bytes(value), bytes(ids[j - 1]))) {
                ids[j] = ids[j - 1];
                --j;
            }
            ids[j] = value;
        }
        uint256 count;
        for (uint256 i; i < ids.length; ++i) {
            if (count == 0 || keccak256(bytes(ids[i])) != keccak256(bytes(ids[count - 1]))) {
                ids[count++] = ids[i];
            }
        }
        assembly ("memory-safe") { mstore(ids, count) }
        return keccak256(abi.encode(bytes32("ATKJ_ADVISORY_IDS_V1"), ids));
    }

    function _less(bytes memory a, bytes memory b) private pure returns (bool) {
        uint256 limit = a.length < b.length ? a.length : b.length;
        for (uint256 i; i < limit; ++i) {
            if (a[i] != b[i]) return uint8(a[i]) < uint8(b[i]);
        }
        return a.length < b.length;
    }
}
