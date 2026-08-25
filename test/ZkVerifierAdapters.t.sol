// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerificationResult} from "../src/interfaces/external/ISnpAttestation.sol";
import {AmdSevSnpVerifierJournal, IntelTdxDcapCompactOutputV1, ProgramBoundZkProof} from "../src/types/Zk.sol";
import {AmdSevSnpZkVerifierAdapter, IntelTdxDcapZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {MockAutomataDcapAttestation} from "./mocks/MockAutomataDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "./mocks/MockAutomataSnpAttestation.sol";

contract IntelTdxDcapZkVerifierAdapterTest is Test {
    bytes32 private constant PROGRAM_IDENTIFIER = 0x00ed85153a35a84ea1fff62d16ac42f850082f11caea923bf25c20a432bdae46;
    uint32 private constant TCB_EVALUATION_DATA_NUMBER = 19;

    MockAutomataDcapAttestation private dcapAttestation;
    IntelTdxDcapZkVerifierAdapter private adapter;

    function _compactOutputV1(
        bytes16 formatGuard,
        bytes4 magic,
        uint16 formatType,
        uint16 formatVersion,
        bytes32 fullQuoteHash,
        bytes32 quoteBodyHash,
        bytes32 advisoryIdsHash
    ) private pure returns (bytes memory) {
        return abi.encodePacked(
            uint16(4),
            uint16(2),
            uint8(5),
            bytes6(0x010203040506),
            formatGuard,
            magic,
            formatType,
            formatVersion,
            fullQuoteHash,
            quoteBodyHash,
            advisoryIdsHash
        );
    }

    function _proof(bytes memory output) private pure returns (ProgramBoundZkProof memory) {
        bytes memory journal = abi.encodePacked(uint16(output.length), output, bytes32(uint256(1)));
        return ProgramBoundZkProof({programIdentifier: PROGRAM_IDENTIFIER, output: journal, proofBytes: hex"01020304"});
    }

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
        bytes32 advisoryIdsHash = keccak256("canonical Intel advisory IDs");
        bytes memory expectedOutput =
            _compactOutputV1(bytes16(0), 0x41544b4a, 1, 1, fullQuoteHash, quoteBodyHash, advisoryIdsHash);

        IntelTdxDcapCompactOutputV1 memory actualOutput = adapter.verifyProof(_proof(expectedOutput));

        assertEq(actualOutput.quoteVersion, 4);
        assertEq(actualOutput.quoteBodyType, 2);
        assertEq(actualOutput.tcbStatus, 5);
        assertEq(actualOutput.fmspc, bytes6(0x010203040506));
        assertEq(actualOutput.fullQuoteHash, fullQuoteHash);
        assertEq(actualOutput.quoteBodyHash, quoteBodyHash);
        assertEq(actualOutput.advisoryIdsHash, advisoryIdsHash);
        assertEq(dcapAttestation.lastProgramIdentifier(), PROGRAM_IDENTIFIER);
        assertEq(dcapAttestation.lastTcbEvaluationDataNumber(), TCB_EVALUATION_DATA_NUMBER);
    }

    function testRejectsNonCanonicalCompactOutputLength() public {
        bytes memory expectedOutput = new bytes(130);

        vm.expectRevert(
            abi.encodeWithSelector(IntelTdxDcapZkVerifierAdapter.InvalidDcapCompactOutputLength.selector, 130, 131)
        );
        adapter.verifyProof(_proof(expectedOutput));
    }

    function testCompactOutputAdapterRejectsLegacyOutput() public {
        bytes memory legacyOutput = new bytes(75);

        vm.expectRevert(
            abi.encodeWithSelector(IntelTdxDcapZkVerifierAdapter.InvalidDcapCompactOutputLength.selector, 75, 131)
        );
        adapter.verifyProof(_proof(legacyOutput));
    }

    function testRejectsNonzeroCompactOutputFormatGuard() public {
        bytes memory output =
            _compactOutputV1(bytes16(uint128(1)), 0x41544b4a, 1, 1, bytes32(0), bytes32(0), bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IntelTdxDcapZkVerifierAdapter.InvalidDcapCompactOutputFormatGuard.selector, bytes16(uint128(1))
            )
        );
        adapter.verifyProof(_proof(output));
    }

    function testRejectsWrongMagic() public {
        bytes memory output = _compactOutputV1(bytes16(0), 0x42414421, 1, 1, bytes32(0), bytes32(0), bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(
                IntelTdxDcapZkVerifierAdapter.InvalidDcapCompactOutputMagic.selector, bytes4(0x42414421)
            )
        );
        adapter.verifyProof(_proof(output));
    }

    function testRejectsUnsupportedFormatType() public {
        bytes memory output = _compactOutputV1(bytes16(0), 0x41544b4a, 2, 1, bytes32(0), bytes32(0), bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(IntelTdxDcapZkVerifierAdapter.UnsupportedDcapCompactOutputType.selector, 2)
        );
        adapter.verifyProof(_proof(output));
    }

    function testRejectsUnsupportedFormatVersion() public {
        bytes memory output = _compactOutputV1(bytes16(0), 0x41544b4a, 1, 2, bytes32(0), bytes32(0), bytes32(0));

        vm.expectRevert(
            abi.encodeWithSelector(IntelTdxDcapZkVerifierAdapter.UnsupportedDcapCompactOutputVersion.selector, 2)
        );
        adapter.verifyProof(_proof(output));
    }

    function testAdvisoryHashEncodingMatchesRust() public pure {
        string[] memory advisoryIds = new string[](2);
        advisoryIds[0] = "INTEL-SA-00001";
        advisoryIds[1] = "INTEL-SA-00002";

        assertEq(
            keccak256(abi.encode(bytes32("ATKJ_ADVISORY_IDS_V1"), advisoryIds)),
            0x74e331084383d7664e2286bc530b1be303d794a53fa76fe96418d6f00f6c6164
        );
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
