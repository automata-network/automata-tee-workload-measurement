// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerificationResult} from "../src/interfaces/external/ISnpAttestation.sol";
import {AmdSevSnpVerifierJournal, IntelTdxDcapJournalV1, ProgramBoundZkProof} from "../src/types/Zk.sol";
import {AmdSevSnpZkVerifierAdapter, IntelTdxDcapZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {MockAutomataDcapAttestation} from "./mocks/MockAutomataDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "./mocks/MockAutomataSnpAttestation.sol";

contract IntelTdxDcapZkVerifierAdapterTest is Test {
    bytes32 private constant PROGRAM_IDENTIFIER = 0x003e867031f3ecfb37bfa94d669b407a3ddb9b4e6e051201226d8bdad3a49120;
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

contract AmdSevSnpZkVerifierAdapterTest is Test {
    bytes32 private constant PROGRAM_IDENTIFIER = keccak256("amd_sev_snp.v1.selected");
    bytes32 private constant IMPLICIT_LATEST_PROGRAM_IDENTIFIER = keccak256("amd_sev_snp.v1.latest");

    MockAutomataSnpAttestation private snpAttestation;
    AmdSevSnpZkVerifierAdapter private adapter;

    function setUp() public {
        snpAttestation = new MockAutomataSnpAttestation();
        snpAttestation.setLatestProgramIdentifier(IMPLICIT_LATEST_PROGRAM_IDENTIFIER);
        adapter = new AmdSevSnpZkVerifierAdapter(
            ISnpAttestation(address(snpAttestation)), ISnpAttestation.ZkCoProcessorType.Succinct
        );
    }

    function testPassesExactProgramIdentifierAndPreservesPackedJournalParsing() public {
        bytes32 reportHash = keccak256("AMD SEV-SNP report");
        bytes32 firstCert = keccak256("AMD ARK");
        bytes32 secondCert = keccak256("AMD ASK");
        uint160 firstSerial = uint160(0x1234);
        uint160 secondSerial = uint160(0x5678);
        bytes memory output = abi.encodePacked(
            uint8(VerificationResult.Success),
            uint64(1_700_000_000),
            uint8(1),
            uint32(2),
            firstCert,
            secondCert,
            firstSerial,
            secondSerial,
            reportHash
        );
        ProgramBoundZkProof memory proof =
            ProgramBoundZkProof({programIdentifier: PROGRAM_IDENTIFIER, output: output, proofBytes: hex"01020304"});

        AmdSevSnpVerifierJournal memory journal = adapter.verifyProof(proof);

        assertEq(uint8(journal.result), uint8(VerificationResult.Success));
        assertEq(journal.timestamp, 1_700_000_000);
        assertEq(journal.processorModel, 1);
        assertEq(journal.reportHash, reportHash);
        assertEq(journal.certs.length, 2);
        assertEq(journal.certs[0], firstCert);
        assertEq(journal.certs[1], secondCert);
        assertEq(journal.certSerials.length, 2);
        assertEq(journal.certSerials[0], firstSerial);
        assertEq(journal.certSerials[1], secondSerial);
        assertEq(snpAttestation.lastProgramIdentifier(), PROGRAM_IDENTIFIER);
        assertTrue(snpAttestation.lastProgramIdentifier() != snpAttestation.latestProgramIdentifier());
        assertEq(uint8(snpAttestation.lastZkCoProcessorType()), uint8(ISnpAttestation.ZkCoProcessorType.Succinct));
        assertEq(snpAttestation.callCount(), 1);
    }
}
