// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {SessionRegistry} from "../src/SessionRegistry.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {PcrSpec, PcrVerifyType} from "../src/types/Common.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

/// @dev Harness exposing the internal PCR evaluator for direct testing without the
///      registerSession attestation pipeline.
contract SessionRegistryHarness is SessionRegistry {
    constructor()
        SessionRegistry(
            ITeeVerifier(address(0)),
            ITpmAttestation(address(0)),
            ISignatureVerifier(address(0)),
            IAkCollateralVerifier(address(0)),
            IBaseImageRegistry(address(0)),
            IWorkloadRegistry(address(0))
        )
    {}

    function evaluateSinglePcr(PcrSpec memory spec, PcrValue memory measured) external pure {
        _evaluateSinglePcr(spec, measured);
    }
}

contract PcrEvalEmptyEventLogTest is Test {
    SessionRegistryHarness internal harness;

    // Pulled from SessionRegistry's error declarations
    error PCRVerificationFailed();

    function setUp() public {
        harness = new SessionRegistryHarness();
    }

    function _matchSet() internal pure returns (bytes32[] memory) {
        bytes32[] memory m = new bytes32[](2);
        m[0] = bytes32(uint256(0xa1));
        m[1] = bytes32(uint256(0xa2));
        return m;
    }

    function _measured(bytes32[] memory events) internal pure returns (PcrValue memory) {
        return PcrValue({pcrIndex: 0, value: bytes32(0), eventLogHashes: events});
    }

    // ─── DYNAMIC_SUBSET ──────────────────────────────────────────────────────────

    function testDynamicSubset_RevertsOnEmptyEventLog() public {
        PcrSpec memory spec = PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        PcrValue memory measured = _measured(new bytes32[](0));
        vm.expectRevert(PCRVerificationFailed.selector);
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubset_AcceptsNonEmptySubset() public view {
        bytes32[] memory events = new bytes32[](2);
        events[0] = bytes32(uint256(0xa1));
        events[1] = bytes32(uint256(0xa2));
        PcrSpec memory spec = PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        harness.evaluateSinglePcr(spec, _measured(events)); // no revert
    }

    function testDynamicSubset_RevertsOnEventOutsideMatchSet() public {
        bytes32[] memory events = new bytes32[](1);
        events[0] = bytes32(uint256(0xdead));
        PcrSpec memory spec = PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: _matchSet()});
        vm.expectRevert(PCRVerificationFailed.selector);
        harness.evaluateSinglePcr(spec, _measured(events));
    }

    // ─── DYNAMIC_SUBSEQUENCE ─────────────────────────────────────────────────────

    function testDynamicSubsequence_RevertsOnEmptyEventLog() public {
        PcrSpec memory spec =
            PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSEQUENCE, matchData: _matchSet()});
        PcrValue memory measured = _measured(new bytes32[](0));
        vm.expectRevert(PCRVerificationFailed.selector);
        harness.evaluateSinglePcr(spec, measured);
    }

    function testDynamicSubsequence_AcceptsExactSequence() public view {
        bytes32[] memory events = new bytes32[](2);
        events[0] = bytes32(uint256(0xa1));
        events[1] = bytes32(uint256(0xa2));
        PcrSpec memory spec =
            PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.DYNAMIC_SUBSEQUENCE, matchData: _matchSet()});
        harness.evaluateSinglePcr(spec, _measured(events)); // no revert
    }
}
