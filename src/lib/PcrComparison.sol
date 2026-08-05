// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Bytes48} from "./LibBytes.sol";

/// @notice Canonical opaque PCR comparison encodings.
/// @dev Every comparison is `abi.encode(uint16 comparisonType, type-specific fields...)`.
///      A decoder must re-encode the decoded value and require byte-for-byte equality
///      with the supplied comparison before evaluating it.
library PcrComparison {
    uint16 internal constant STATIC = 0;
    uint16 internal constant DYNAMIC_SUBSET = 1;
    uint16 internal constant DYNAMIC_SUBSEQUENCE = 2;
    uint16 internal constant DYNAMIC_INDEXED_EVENT_SETS = 3;
    uint16 internal constant EXTEND_FROM_ZERO = 4;

    struct IndexedEventSet256 {
        uint16 eventIndex;
        bytes32[] allowedValues;
    }

    struct IndexedEventSets256 {
        uint16 expectedEventCount;
        IndexedEventSet256[] checkedEvents;
    }

    struct IndexedEventSet384 {
        uint16 eventIndex;
        Bytes48[] allowedValues;
    }

    struct IndexedEventSets384 {
        uint16 expectedEventCount;
        IndexedEventSet384[] checkedEvents;
    }

    function encodeStatic256(bytes32 expectedValue) internal pure returns (bytes memory) {
        return abi.encode(STATIC, expectedValue);
    }

    function encodeStatic384(Bytes48 memory expectedValue) internal pure returns (bytes memory) {
        return abi.encode(STATIC, expectedValue);
    }

    function encodeDynamic256(uint16 comparisonType, bytes32[] memory landmarks) internal pure returns (bytes memory) {
        return abi.encode(comparisonType, landmarks);
    }

    function encodeDynamic384(uint16 comparisonType, Bytes48[] memory landmarks) internal pure returns (bytes memory) {
        return abi.encode(comparisonType, landmarks);
    }

    function encodeIndexedEventSets256(IndexedEventSets256 memory rule) internal pure returns (bytes memory) {
        return abi.encode(DYNAMIC_INDEXED_EVENT_SETS, rule);
    }

    function encodeIndexedEventSets384(IndexedEventSets384 memory rule) internal pure returns (bytes memory) {
        return abi.encode(DYNAMIC_INDEXED_EVENT_SETS, rule);
    }

    function encodeExtendFromZero256(bytes32 extendValue) internal pure returns (bytes memory) {
        return abi.encode(EXTEND_FROM_ZERO, extendValue);
    }

    function encodeExtendFromZero384(Bytes48 memory extendValue) internal pure returns (bytes memory) {
        return abi.encode(EXTEND_FROM_ZERO, extendValue);
    }
}
