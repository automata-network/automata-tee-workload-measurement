// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {LibBytes as SoladyLibBytes} from "@solady/utils/LibBytes.sol";

using LibBytes for Bytes48 global;
using LibBytes for Bytes64 global;

struct Bytes64 {
    bytes32 first;
    bytes32 second;
}

struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

library LibBytes {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";

    /// @notice Byte array length is invalid
    error InvalidLength();

    /// @notice A fixed-width read extends past the logical end of the byte array.
    error ReadOutOfBounds(uint256 offset, uint256 requiredLength, uint256 actualLength);

    function readBytes48(bytes memory input, uint256 offset) internal pure returns (Bytes48 memory output) {
        _requireAvailable(input, offset, 48);
        // The EVM mload instruction always reads one 32-byte word. The second mload reads
        // the final 16 value bytes plus 16 bytes of Solidity's word-aligned array padding.
        assembly ("memory-safe") {
            function store48(dest, src, off) {
                mstore(dest, mload(add(add(src, 0x20), off)))
                mstore(add(dest, 0x20), mload(add(add(src, 0x40), off)))
            }
            store48(output, input, offset)
        }
    }

    function readBytes64(bytes memory input, uint256 offset) internal pure returns (Bytes64 memory output) {
        _requireAvailable(input, offset, 64);
        assembly ("memory-safe") {
            function store64(dest, src, off) {
                mstore(dest, mload(add(add(src, 0x20), off)))
                mstore(add(dest, 0x20), mload(add(add(src, 0x40), off)))
            }
            store64(output, input, offset)
        }
    }

    function readBytes2(bytes memory input, uint256 offset) internal pure returns (bytes2 output) {
        _requireAvailable(input, offset, 2);
        // mload reads 32 bytes; bytes2 keeps the leading two bytes. Any remaining bytes
        // come from the array data or its word-aligned allocation padding.
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    function readBytes4(bytes memory input, uint256 offset) internal pure returns (bytes4 output) {
        _requireAvailable(input, offset, 4);
        // mload reads 32 bytes; bytes4 keeps the leading four bytes.
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    function readBytes32(bytes memory input, uint256 offset) internal pure returns (bytes32 output) {
        _requireAvailable(input, offset, 32);
        assembly ("memory-safe") {
            output := mload(add(add(input, 0x20), offset))
        }
    }

    function toBytes48(bytes memory data) internal pure returns (Bytes48 memory) {
        if (data.length != 48) revert InvalidLength();
        return readBytes48(data, 0);
    }

    function toBytes64(bytes memory data) internal pure returns (Bytes64 memory) {
        if (data.length != 64) revert InvalidLength();
        return readBytes64(data, 0);
    }

    function _requireAvailable(bytes memory input, uint256 offset, uint256 requiredLength) private pure {
        if (offset > input.length || requiredLength > input.length - offset) {
            revert ReadOutOfBounds(offset, requiredLength, input.length);
        }
    }

    function equal(Bytes48 memory a, Bytes48 memory b) internal pure returns (bool) {
        return a.first == b.first && a.second == b.second;
    }

    function equal(bytes memory a, bytes memory b) internal pure returns (bool) {
        return SoladyLibBytes.eq(a, b);
    }

    function isZero(Bytes48 memory data) internal pure returns (bool) {
        return data.first == bytes32(0) && data.second == bytes16(0);
    }

    function toBytes(Bytes48 memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(data.first, data.second);
    }

    function slice(bytes memory subject, uint256 start, uint256 len) internal pure returns (bytes memory result) {
        return SoladyLibBytes.slice(subject, start, start + len);
    }

    function toString(bytes memory data) internal pure returns (string memory) {
        uint256 len = data.length;
        bytes memory buffer = new bytes(2 + len * 2);
        buffer[0] = "0";
        buffer[1] = "x";

        for (uint256 i; i < len; ++i) {
            uint8 b = uint8(data[i]);
            buffer[2 + i * 2] = _SYMBOLS[b >> 4];
            buffer[3 + i * 2] = _SYMBOLS[b & 0x0f];
        }
        return string(buffer);
    }

    function toString(Bytes64 memory data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data.first, data.second));
    }

    function toString(Bytes48 memory data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data.first, data.second));
    }

    function toString(uint256 data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data));
    }

    function toString(bytes32 data) internal pure returns (string memory) {
        return toString(abi.encodePacked(data));
    }
}
