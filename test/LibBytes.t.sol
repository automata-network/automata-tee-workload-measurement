// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {LibBytes, Bytes48, Bytes64} from "../src/lib/LibBytes.sol";

contract LibBytesHarness {
    function read2(bytes memory input, uint256 offset) external pure returns (bytes2) {
        return LibBytes.readBytes2(input, offset);
    }

    function read4(bytes memory input, uint256 offset) external pure returns (bytes4) {
        return LibBytes.readBytes4(input, offset);
    }

    function read32(bytes memory input, uint256 offset) external pure returns (bytes32) {
        return LibBytes.readBytes32(input, offset);
    }

    function read48(bytes memory input, uint256 offset) external pure returns (bytes memory) {
        Bytes48 memory value = LibBytes.readBytes48(input, offset);
        return LibBytes.toBytes(value);
    }

    function read64(bytes memory input, uint256 offset) external pure returns (bytes32 first, bytes32 second) {
        Bytes64 memory value = LibBytes.readBytes64(input, offset);
        return (value.first, value.second);
    }
}

contract LibBytesTest is Test {
    LibBytesHarness private harness;

    function setUp() public {
        harness = new LibBytesHarness();
    }

    function testFixedWidthReadsAcceptExactLogicalBoundary() public view {
        bytes memory input = _sequentialBytes(64);

        assertEq(harness.read2(input, 62), bytes2(hex"3f40"));
        assertEq(harness.read4(input, 60), bytes4(hex"3d3e3f40"));
        assertEq(harness.read32(input, 32), bytes32(_sliceWord(input, 32)));

        bytes memory value48 = harness.read48(input, 16);
        assertEq(value48.length, 48);
        assertEq(uint8(value48[0]), 17);
        assertEq(uint8(value48[47]), 64);

        (bytes32 first, bytes32 second) = harness.read64(input, 0);
        assertEq(first, bytes32(_sliceWord(input, 0)));
        assertEq(second, bytes32(_sliceWord(input, 32)));
    }

    function testFixedWidthReadsRejectOneByteShort() public {
        _expectOutOfBounds(1, 2, 2);
        harness.read2(new bytes(2), 1);

        _expectOutOfBounds(1, 4, 4);
        harness.read4(new bytes(4), 1);

        _expectOutOfBounds(1, 32, 32);
        harness.read32(new bytes(32), 1);

        _expectOutOfBounds(1, 48, 48);
        harness.read48(new bytes(48), 1);

        _expectOutOfBounds(1, 64, 64);
        harness.read64(new bytes(64), 1);
    }

    function testFixedWidthReadRejectsOffsetPastEndWithoutOverflow() public {
        vm.expectRevert(
            abi.encodeWithSelector(LibBytes.ReadOutOfBounds.selector, type(uint256).max, uint256(32), uint256(1))
        );
        harness.read32(new bytes(1), type(uint256).max);
    }

    function _expectOutOfBounds(uint256 offset, uint256 requiredLength, uint256 actualLength) private {
        vm.expectRevert(abi.encodeWithSelector(LibBytes.ReadOutOfBounds.selector, offset, requiredLength, actualLength));
    }

    function _sequentialBytes(uint256 length) private pure returns (bytes memory output) {
        output = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            output[i] = bytes1(uint8(i + 1));
        }
    }

    function _sliceWord(bytes memory input, uint256 offset) private pure returns (bytes32 word) {
        assembly ("memory-safe") {
            word := mload(add(add(input, 0x20), offset))
        }
    }
}
