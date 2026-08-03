// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {IntelTdxDcapJournalV1, ProgramBoundZkProof} from "../src/types/Zk.sol";
import {IntelTdxDcapZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {MockAutomataDcapAttestation} from "./mocks/MockAutomataDcapAttestation.sol";

contract IntelTdxDcapZkVerifierAdapterTest is Test {
    bytes32 private constant PROGRAM_IDENTIFIER = 0x002973c41c78fbad885b2331b84bcd36df9f01d20c12efd8a969d709154f5dc5;
    uint32 private constant TCB_EVALUATION_DATA_NUMBER = 19;

    MockAutomataDcapAttestation private dcapAttestation;
    IntelTdxDcapZkVerifierAdapter private adapter;

    function setUp() public {
        dcapAttestation = new MockAutomataDcapAttestation();
        adapter = new IntelTdxDcapZkVerifierAdapter(
            IDcapAttestation(address(dcapAttestation)),
            IDcapAttestation.ZkCoProcessorType.Succinct,
            TCB_EVALUATION_DATA_NUMBER
        );
    }

    function testPassesProgramIdentifierAndTcbEvaluationDataNumber() public {
        bytes32 fullQuoteHash = keccak256("full Intel TDX quote");
        bytes32 quoteBodyHash = keccak256("Intel TDX quote body");
        bytes memory expectedOutput =
            abi.encodePacked(uint16(4), uint16(2), uint8(5), bytes6(0x010203040506), fullQuoteHash, quoteBodyHash);
        bytes memory journal = abi.encodePacked(uint16(expectedOutput.length), expectedOutput, bytes32(uint256(1)));
        ProgramBoundZkProof memory proof =
            ProgramBoundZkProof({programIdentifier: PROGRAM_IDENTIFIER, output: journal, proofBytes: hex"01020304"});

        IntelTdxDcapJournalV1 memory actualOutput = adapter.verifyProof(proof);

        assertEq(actualOutput.quoteVersion, 4);
        assertEq(actualOutput.quoteBodyType, 2);
        assertEq(actualOutput.tcbStatus, 5);
        assertEq(actualOutput.fmspc, bytes6(0x010203040506));
        assertEq(actualOutput.fullQuoteHash, fullQuoteHash);
        assertEq(actualOutput.quoteBodyHash, quoteBodyHash);
        assertEq(dcapAttestation.lastProgramIdentifier(), PROGRAM_IDENTIFIER);
        assertEq(dcapAttestation.lastTcbEvaluationDataNumber(), TCB_EVALUATION_DATA_NUMBER);
    }

    function testRejectsNonCanonicalCompactOutputLength() public {
        bytes memory expectedOutput = new bytes(74);
        bytes memory journal = abi.encodePacked(uint16(expectedOutput.length), expectedOutput);
        ProgramBoundZkProof memory proof =
            ProgramBoundZkProof({programIdentifier: PROGRAM_IDENTIFIER, output: journal, proofBytes: hex""});

        vm.expectRevert(
            abi.encodeWithSelector(IntelTdxDcapZkVerifierAdapter.InvalidDcapJournalOutputLength.selector, 74, 75)
        );
        adapter.verifyProof(proof);
    }
}
