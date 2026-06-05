// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {ISnpAttestation, VerificationResult} from "../src/interfaces/external/ISnpAttestation.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "../src/mock/MockAutomataSnpAttestation.sol";
import {MockAutomataDcapAttestation} from "../src/mock/MockAutomataDcapAttestation.sol";
import {
    TeeReport,
    TEEType,
    VerificationBackendType,
    SnpZkProof,
    TeeVerificationResult
} from "../src/types/Evidence.sol";

/// @notice Exercises the SEV-SNP path of TeeVerifier against the SDK journal layout
///         (VerifierJournal.reportHash = keccak256(report)), including the report-binding guard.
contract TeeVerifierSnpTest is Test {
    TeeVerifier internal teeVerifier;
    MockAutomataSnpAttestation internal snp;
    MockAutomataDcapAttestation internal dcap;

    function setUp() public {
        snp = new MockAutomataSnpAttestation();
        dcap = new MockAutomataDcapAttestation();
        teeVerifier = new TeeVerifier(IDcapAttestation(address(dcap)), ISnpAttestation(address(snp)));
    }

    /// @dev A deterministic, full-size (1184-byte) SEV-SNP report.
    function _report() internal pure returns (bytes memory r) {
        r = new bytes(1184);
        for (uint256 i = 0; i < r.length; i++) {
            r[i] = bytes1(uint8(i));
        }
    }

    /// @dev The SDK's *packed* zkVM public journal (matches SEVAgentAttestation._parseJournal), with
    ///      certSize=0 so reportHash is the trailing 32 bytes. This is what the prover emits and what
    ///      the mock parses — not abi.encode.
    function _packedJournal(VerificationResult result, bytes32 reportHash) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(result), // u8  result
            uint64(1_700_000_000), // u64 timestamp (big-endian)
            uint8(1), // u8  processorModel
            uint32(0), // u32 certSize (no certs/serials)
            reportHash // bytes32 reportHash (trailing 32 bytes)
        );
    }

    function _teeReport(bytes memory journalOutput, bytes memory rawReport) internal pure returns (TeeReport memory) {
        SnpZkProof memory p = SnpZkProof({output: journalOutput, proofBytes: hex"", rawReport: rawReport});
        return TeeReport({
            verificationBackendType: VerificationBackendType.ZkRiscZero, teeType: TEEType.AmdSevSnp, data: abi.encode(p)
        });
    }

    function test_snp_happyPath_returnsFullReport() public {
        bytes memory report = _report();
        TeeReport memory tr = _teeReport(_packedJournal(VerificationResult.Success, keccak256(report)), report);

        TeeVerificationResult memory res = teeVerifier.verifyTeeReport(tr);

        assertTrue(res.valid);
        assertEq(uint8(res.teeType), uint8(TEEType.AmdSevSnp));
        // _verifyAmdSevSnp returns the full bound report as reportData.
        assertEq(res.reportData, report);
    }

    function test_snp_revert_on_reportHash_mismatch() public {
        bytes memory report = _report();
        bytes32 wrongHash = keccak256("a different report");
        // Valid proof/journal, but the supplied report body does not match journal.reportHash.
        TeeReport memory tr = _teeReport(_packedJournal(VerificationResult.Success, wrongHash), report);

        vm.expectRevert(
            abi.encodeWithSelector(TeeVerifier.SnpReportHashMismatch.selector, wrongHash, keccak256(report))
        );
        teeVerifier.verifyTeeReport(tr);
    }

    function test_snp_revert_on_verifier_failure() public {
        bytes memory report = _report();
        TeeReport memory tr = _teeReport(_packedJournal(VerificationResult.InvalidTimestamp, keccak256(report)), report);

        vm.expectRevert(
            abi.encodeWithSelector(TeeVerifier.SnpVerificationFailed.selector, VerificationResult.InvalidTimestamp)
        );
        teeVerifier.verifyTeeReport(tr);
    }

    /// @dev Session-ID binding: getTeeReportHash reads the trailing 32 bytes of the packed journal,
    ///      which the SDK places reportHash at. Also exercises the SnpZkProof→ZkProof forward-compat
    ///      decode (getTeeReportHash decodes as ZkProof and must still read `output`).
    function test_snp_getTeeReportHash_equals_reportHash() public view {
        bytes memory report = _report();
        bytes32 reportHash = keccak256(report);
        TeeReport memory tr = _teeReport(_packedJournal(VerificationResult.Success, reportHash), report);

        assertEq(teeVerifier.getTeeReportHash(tr), reportHash);
    }
}
