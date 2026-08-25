// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {PcrComparison} from "../src/lib/PcrComparison.sol";
import {PcrSpec256} from "../src/types/Common.sol";
import {PcrValue256} from "../src/types/Evidence.sol";

error InvalidPcrRule(uint16 algorithm, uint8 pcrIndex);
error NonCanonicalPcrComparison(uint16 algorithm, uint8 pcrIndex);
error PcrEventLogEmpty(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType);
error PcrSubsetLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 landmarkIndex);
error PcrEventCountMismatch(uint16 algorithm, uint8 pcrIndex, uint256 actual, uint16 expected);
error PcrCheckedEventIndexOutOfRange(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex, uint16 eventCount);
error PcrCheckedEventIndexesNotSorted(uint16 algorithm, uint8 pcrIndex, uint16 previous, uint16 current);
error PcrAllowedValuesEmpty(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);
error PcrAllowedValuesNotSorted(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex, uint256 position);
error PcrIndexedEventSetMismatch(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);

contract TpmVerifierEvaluationHarness is TpmVerifier {
    constructor() TpmVerifier(ITpmAttestation(address(0)), IZkVerifierRegistry(address(0))) {}

    function evaluateSinglePcr(PcrSpec256 memory spec, PcrValue256 memory measured) external pure {
        _evaluateSinglePcr256(spec, measured, 0xff);
    }
}

contract PcrEvalEmptyEventLogTest is Test {
    uint16 private constant TPM_ALG_SHA256 = 0x000b;

    TpmVerifierEvaluationHarness internal harness;

    function setUp() public {
        harness = new TpmVerifierEvaluationHarness();
    }

    function testStatic_AcceptsCanonicalComparison() public view {
        bytes32 expected = bytes32(uint256(0xa1));
        PcrSpec256 memory spec = _staticSpec(expected);
        PcrValue256 memory measured = PcrValue256({pcrIndex: 0, value: expected, eventLogHashes: new bytes32[](0)});
        harness.evaluateSinglePcr(spec, measured);
    }

    function testStatic_RejectsTrailingData() public {
        bytes memory comparison =
            bytes.concat(PcrComparison.encodeStatic256(bytes32(uint256(0xa1))), bytes32(uint256(0xa2)));
        PcrSpec256 memory spec = PcrSpec256({pcrIndex: 0, comparison: comparison});
        PcrValue256 memory measured =
            PcrValue256({pcrIndex: 0, value: bytes32(uint256(0xa1)), eventLogHashes: new bytes32[](0)});

        vm.expectRevert(abi.encodeWithSelector(NonCanonicalPcrComparison.selector, TPM_ALG_SHA256, uint8(0)));
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubset_RevertsOnEmptyEventLog() public {
        PcrSpec256 memory spec = _dynamicSpec(PcrComparison.DYNAMIC_SUBSET, _matchSet());
        PcrValue256 memory measured = _measured(new bytes32[](0));
        vm.expectRevert(
            abi.encodeWithSelector(PcrEventLogEmpty.selector, TPM_ALG_SHA256, uint8(0), PcrComparison.DYNAMIC_SUBSET)
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubset_AcceptsRequiredLandmarksWithExtraEventsInAnyOrder() public view {
        bytes32[] memory events = new bytes32[](4);
        events[0] = bytes32(uint256(0xdead));
        events[1] = bytes32(uint256(0xa2));
        events[2] = bytes32(uint256(0xbeef));
        events[3] = bytes32(uint256(0xa1));
        harness.evaluateSinglePcr(_dynamicSpec(PcrComparison.DYNAMIC_SUBSET, _matchSet()), _measured(events));
    }

    function testDynamicSubset_RevertsWhenRequiredLandmarkIsMissing() public {
        bytes32[] memory events = new bytes32[](2);
        events[0] = bytes32(uint256(0xdead));
        events[1] = bytes32(uint256(0xa1));
        PcrSpec256 memory spec = _dynamicSpec(PcrComparison.DYNAMIC_SUBSET, _matchSet());
        PcrValue256 memory measured = _measured(events);

        vm.expectRevert(abi.encodeWithSelector(PcrSubsetLandmarkMissing.selector, TPM_ALG_SHA256, uint8(0), uint256(1)));
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubsequence_RevertsOnEmptyEventLog() public {
        PcrSpec256 memory spec = _dynamicSpec(PcrComparison.DYNAMIC_SUBSEQUENCE, _matchSet());
        PcrValue256 memory measured = _measured(new bytes32[](0));
        vm.expectRevert(
            abi.encodeWithSelector(
                PcrEventLogEmpty.selector, TPM_ALG_SHA256, uint8(0), PcrComparison.DYNAMIC_SUBSEQUENCE
            )
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubsequence_AcceptsExactSequence() public view {
        bytes32[] memory events = _matchSet();
        harness.evaluateSinglePcr(_dynamicSpec(PcrComparison.DYNAMIC_SUBSEQUENCE, _matchSet()), _measured(events));
    }

    function testDynamicIndexedEventSets_AcceptsSkippedIndexesAndAllowedValues() public view {
        bytes32[] memory events = _indexedEvents();
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](2);
        checkedEvents[0] = _checkedEvent(0, _values(bytes32(uint256(0x0f)), events[0]));
        checkedEvents[1] = _checkedEvent(3, _values(events[3], bytes32(uint256(0x4f))));

        harness.evaluateSinglePcr(_indexedSpec(4, checkedEvents), _measured(events));
    }

    function testDynamicIndexedEventSets_RejectsWrongEventCount() public {
        bytes32[] memory events = _indexedEvents();
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](1);
        checkedEvents[0] = _checkedEvent(0, _values(events[0], bytes32(uint256(0x1f))));
        PcrSpec256 memory spec = _indexedSpec(5, checkedEvents);
        PcrValue256 memory measured = _measured(events);

        vm.expectRevert(
            abi.encodeWithSelector(PcrEventCountMismatch.selector, TPM_ALG_SHA256, uint8(0), uint256(4), uint16(5))
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicIndexedEventSets_RejectsUncheckedValueAtCheckedIndex() public {
        bytes32[] memory events = _indexedEvents();
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](1);
        checkedEvents[0] = _checkedEvent(2, _values(bytes32(uint256(0x2f)), bytes32(uint256(0x31))));
        PcrSpec256 memory spec = _indexedSpec(4, checkedEvents);
        PcrValue256 memory measured = _measured(events);

        vm.expectRevert(
            abi.encodeWithSelector(PcrIndexedEventSetMismatch.selector, TPM_ALG_SHA256, uint8(0), uint16(2))
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicIndexedEventSets_RejectsDuplicateCheckedIndex() public {
        bytes32[] memory events = _indexedEvents();
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](2);
        checkedEvents[0] = _checkedEvent(1, _values(events[1], bytes32(uint256(0x2f))));
        checkedEvents[1] = _checkedEvent(1, _values(events[1], bytes32(uint256(0x2f))));
        PcrSpec256 memory spec = _indexedSpec(4, checkedEvents);
        PcrValue256 memory measured = _measured(events);

        vm.expectRevert(
            abi.encodeWithSelector(
                PcrCheckedEventIndexesNotSorted.selector, TPM_ALG_SHA256, uint8(0), uint16(1), uint16(1)
            )
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicIndexedEventSets_RejectsOutOfRangeCheckedIndex() public {
        bytes32[] memory events = _indexedEvents();
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](1);
        checkedEvents[0] = _checkedEvent(4, _values(bytes32(uint256(0x40)), bytes32(uint256(0x4f))));
        PcrSpec256 memory spec = _indexedSpec(4, checkedEvents);
        PcrValue256 memory measured = _measured(events);

        vm.expectRevert(
            abi.encodeWithSelector(
                PcrCheckedEventIndexOutOfRange.selector, TPM_ALG_SHA256, uint8(0), uint16(4), uint16(4)
            )
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicIndexedEventSets_RejectsEmptyAllowedValues() public {
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](1);
        checkedEvents[0] = _checkedEvent(0, new bytes32[](0));
        PcrSpec256 memory spec = _indexedSpec(4, checkedEvents);
        PcrValue256 memory measured = _measured(_indexedEvents());

        vm.expectRevert(abi.encodeWithSelector(PcrAllowedValuesEmpty.selector, TPM_ALG_SHA256, uint8(0), uint16(0)));
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicIndexedEventSets_RejectsUnsortedAllowedValues() public {
        PcrComparison.IndexedEventSet256[] memory checkedEvents = new PcrComparison.IndexedEventSet256[](1);
        checkedEvents[0] = _checkedEvent(0, _values(bytes32(uint256(0x1f)), bytes32(uint256(0x10))));
        PcrSpec256 memory spec = _indexedSpec(4, checkedEvents);
        PcrValue256 memory measured = _measured(_indexedEvents());

        vm.expectRevert(
            abi.encodeWithSelector(PcrAllowedValuesNotSorted.selector, TPM_ALG_SHA256, uint8(0), uint16(0), uint256(1))
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function _staticSpec(bytes32 expected) private pure returns (PcrSpec256 memory) {
        return PcrSpec256({pcrIndex: 0, comparison: PcrComparison.encodeStatic256(expected)});
    }

    function _dynamicSpec(uint16 comparisonType, bytes32[] memory matchData) private pure returns (PcrSpec256 memory) {
        return PcrSpec256({pcrIndex: 0, comparison: PcrComparison.encodeDynamic256(comparisonType, matchData)});
    }

    function _indexedSpec(uint16 expectedEventCount, PcrComparison.IndexedEventSet256[] memory checkedEvents)
        private
        pure
        returns (PcrSpec256 memory)
    {
        PcrComparison.IndexedEventSets256 memory comparison = PcrComparison.IndexedEventSets256({
            expectedEventCount: expectedEventCount, checkedEvents: checkedEvents
        });
        return PcrSpec256({pcrIndex: 0, comparison: PcrComparison.encodeIndexedEventSets256(comparison)});
    }

    function _checkedEvent(uint16 eventIndex, bytes32[] memory allowedValues)
        private
        pure
        returns (PcrComparison.IndexedEventSet256 memory)
    {
        return PcrComparison.IndexedEventSet256({eventIndex: eventIndex, allowedValues: allowedValues});
    }

    function _values(bytes32 first, bytes32 second) private pure returns (bytes32[] memory values) {
        values = new bytes32[](2);
        values[0] = first;
        values[1] = second;
    }

    function _matchSet() private pure returns (bytes32[] memory values) {
        return _values(bytes32(uint256(0xa1)), bytes32(uint256(0xa2)));
    }

    function _indexedEvents() private pure returns (bytes32[] memory events) {
        events = new bytes32[](4);
        events[0] = bytes32(uint256(0x10));
        events[1] = bytes32(uint256(0x20));
        events[2] = bytes32(uint256(0x30));
        events[3] = bytes32(uint256(0x40));
    }

    function _measured(bytes32[] memory events) private pure returns (PcrValue256 memory) {
        bytes32 value;
        for (uint256 i; i < events.length; ++i) {
            value = sha256(abi.encodePacked(value, events[i]));
        }
        return PcrValue256({pcrIndex: 0, value: value, eventLogHashes: events});
    }
}
