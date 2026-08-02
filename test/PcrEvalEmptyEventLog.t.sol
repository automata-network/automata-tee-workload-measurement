// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {PcrSpec256, PcrVerifyType} from "../src/types/Common.sol";
import {PcrValue256} from "../src/types/Evidence.sol";

// Re-declare the PCR errors here so tests can reference their selectors.
// The actual definitions live on TpmVerifier. Keeping a parallel
// declaration with matching signatures makes `vm.expectPartialRevert` work.
error InvalidPcrRule(uint16 algorithm, uint8 pcrIndex);
error PcrEventLogEmpty(uint16 algorithm, uint8 pcrIndex, PcrVerifyType verifyType);
error PcrSubsetLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 landmarkIndex);
error PcrSubsequenceLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 matchedCount, uint256 expectedCount);

/// @dev Harness exposing the internal PCR evaluator for direct testing without the
///      registerSession attestation pipeline.
contract TpmVerifierEvaluationHarness is TpmVerifier {
    constructor() TpmVerifier(ITpmAttestation(address(0)), IZkVerifierRegistry(address(0))) {}

    function evaluateSinglePcr(PcrSpec256 memory spec, PcrValue256 memory measured) external pure {
        _evaluateSinglePcr256(spec, measured, 0xff);
    }
}

contract PcrEvalEmptyEventLogTest is Test {
    TpmVerifierEvaluationHarness internal harness;

    function setUp() public {
        harness = new TpmVerifierEvaluationHarness();
    }

    function _matchSet() internal pure returns (bytes32[] memory) {
        bytes32[] memory m = new bytes32[](2);
        m[0] = bytes32(uint256(0xa1));
        m[1] = bytes32(uint256(0xa2));
        return m;
    }

    function _measured(bytes32[] memory events) internal pure returns (PcrValue256 memory) {
        bytes32 value;
        for (uint256 i; i < events.length; ++i) {
            value = sha256(abi.encodePacked(value, events[i]));
        }
        return PcrValue256({pcrIndex: 0, value: value, eventLogHashes: events});
    }

    // ─── STATIC ──────────────────────────────────────────────────────────────────

    function testStatic_RevertsUnlessMatchDataHasExactlyOneEntry() public {
        for (uint256 length = 0; length <= 2; length += 2) {
            PcrSpec256 memory spec =
                PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.STATIC, matchData: new bytes32[](length)});
            vm.expectRevert(abi.encodeWithSelector(InvalidPcrRule.selector, uint16(0x000b), uint8(0)));
            harness.evaluateSinglePcr(spec, _measured(new bytes32[](0)));
        }
    }

    function testStatic_AcceptsExactlyOneMatchDataEntry() public view {
        bytes32[] memory matchData = new bytes32[](1);
        matchData[0] = bytes32(uint256(0xa1));
        PcrSpec256 memory spec = PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.STATIC, matchData: matchData});
        PcrValue256 memory measured = PcrValue256({pcrIndex: 0, value: matchData[0], eventLogHashes: new bytes32[](0)});
        harness.evaluateSinglePcr(spec, measured);
    }

    // ─── DYNAMIC_SUBSET ──────────────────────────────────────────────────────────

    function testDynamicSubset_RevertsOnEmptyEventLog() public {
        PcrSpec256 memory spec =
            PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        PcrValue256 memory measured = _measured(new bytes32[](0));
        vm.expectRevert(
            abi.encodeWithSelector(PcrEventLogEmpty.selector, uint16(0x000b), uint8(0), PcrVerifyType.DYNAMIC_SUBSET)
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubset_AcceptsRequiredLandmarksWithExtraEventsInAnyOrder() public view {
        bytes32[] memory events = new bytes32[](4);
        events[0] = bytes32(uint256(0xdead));
        events[1] = bytes32(uint256(0xa2));
        events[2] = bytes32(uint256(0xbeef));
        events[3] = bytes32(uint256(0xa1));
        PcrSpec256 memory spec =
            PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        harness.evaluateSinglePcr(spec, _measured(events)); // no revert
    }

    function testDynamicSubset_RevertsWhenRequiredLandmarkIsMissing() public {
        bytes32[] memory events = new bytes32[](2);
        events[0] = bytes32(uint256(0xdead));
        events[1] = bytes32(uint256(0xa1));
        PcrSpec256 memory spec =
            PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        PcrValue256 memory measured = _measured(events);
        vm.expectRevert(abi.encodeWithSelector(PcrSubsetLandmarkMissing.selector, uint16(0x000b), uint8(0), uint256(1)));
        harness.evaluateSinglePcr(spec, measured);
    }

    // ─── DYNAMIC_SUBSEQUENCE ─────────────────────────────────────────────────────

    function testDynamicSubsequence_RevertsOnEmptyEventLog() public {
        PcrSpec256 memory spec =
            PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSEQUENCE, matchData: _matchSet()});
        PcrValue256 memory measured = _measured(new bytes32[](0));
        vm.expectRevert(
            abi.encodeWithSelector(
                PcrEventLogEmpty.selector, uint16(0x000b), uint8(0), PcrVerifyType.DYNAMIC_SUBSEQUENCE
            )
        );
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubsequence_AcceptsExactSequence() public view {
        bytes32[] memory events = new bytes32[](2);
        events[0] = bytes32(uint256(0xa1));
        events[1] = bytes32(uint256(0xa2));
        PcrSpec256 memory spec =
            PcrSpec256({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSEQUENCE, matchData: _matchSet()});
        harness.evaluateSinglePcr(spec, _measured(events)); // no revert
    }
}
