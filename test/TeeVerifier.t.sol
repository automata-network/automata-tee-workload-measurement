// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {ISnpAttestation, VerificationResult} from "../src/interfaces/external/ISnpAttestation.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "./mocks/MockAutomataSnpAttestation.sol";
import {MockAutomataDcapAttestation} from "./mocks/MockAutomataDcapAttestation.sol";
import {
    TeeReport,
    TEEType,
    VerificationBackendType,
    SnpZkProof,
    TeeVerificationResult
} from "../src/types/Evidence.sol";
import {
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT
} from "../src/types/Constants.sol";

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

    /// @dev A deterministic, structurally valid, full-size SEV-SNP report.
    function _report() internal pure returns (bytes memory r) {
        r = new bytes(1184);
        r[0] = bytes1(uint8(3)); // VERSION = 3, little-endian
        r[10] = bytes1(uint8(2)); // POLICY reserved bit 17 must be one
        r[0x34] = bytes1(uint8(1)); // ECDSA P-384 with SHA-384
        r[0x188] = bytes1(uint8(0x19)); // CPUID family
        r[0x189] = bytes1(uint8(0x11)); // CPUID model
        r[0x18a] = bytes1(uint8(0x01)); // CPUID stepping
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

    function _setLeUint32(bytes memory data, uint256 offset, uint32 value) internal pure {
        data[offset] = bytes1(uint8(value));
        data[offset + 1] = bytes1(uint8(value >> 8));
        data[offset + 2] = bytes1(uint8(value >> 16));
        data[offset + 3] = bytes1(uint8(value >> 24));
    }

    function _setLeUint64(bytes memory data, uint256 offset, uint64 value) internal pure {
        for (uint256 i = 0; i < 8; i++) {
            data[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function _verifySnp(bytes memory report) internal returns (TeeVerificationResult memory) {
        return
            teeVerifier.verifyTeeReport(
                _teeReport(_packedJournal(VerificationResult.Success, keccak256(report)), report)
            );
    }

    function test_snp_happyPath_returnsFullReport() public {
        bytes memory report = _report();
        TeeReport memory tr = _teeReport(_packedJournal(VerificationResult.Success, keccak256(report)), report);

        TeeVerificationResult memory res = teeVerifier.verifyTeeReport(tr);

        assertTrue(res.valid);
        assertEq(uint8(res.teeType), uint8(TEEType.AmdSevSnp));
        assertEq(res.enabledTeeAttributes, 0);
        assertEq(res.intelTdxTcbStatusBit, 0);
        assertEq(res.amdSevSnpTcbValues, bytes32(0));
        assertEq(res.amdSevSnpPlatformInfo, 0);
        assertEq(res.amdSevSnpCpuid, 0x191101);
        assertEq(res.amdSevSnpReportVersion, 3);
        assertEq(res.amdSevSnpLaunchMitigationVector, 0);
        assertEq(res.amdSevSnpCurrentMitigationVector, 0);
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

    function test_snp_extracts_debug_and_migrate_ma() public {
        bytes memory report = _report();
        _setLeUint64(report, 8, (uint64(1) << 17) | (uint64(1) << 18) | (uint64(1) << 19));

        TeeVerificationResult memory result = _verifySnp(report);

        assertEq(
            result.enabledTeeAttributes, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT | TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT
        );
    }

    function test_snp_extracts_tcb_platform_info_and_cpuid() public {
        bytes memory report = _report();
        _setRawTcb(report, 0x38, 5, 1, 30, 223);
        _setRawTcb(report, 0x180, 4, 0, 29, 222);
        _setRawTcb(report, 0x1e0, 4, 1, 29, 222);
        _setRawTcb(report, 0x1f0, 3, 0, 28, 221);
        _setLeUint64(report, 0x40, 0x21);

        TeeVerificationResult memory result = _verifySnp(report);

        assertEq(result.amdSevSnpTcbValues, 0x00000000df1e010500000000de1d000400000000de1d010400000000dd1c0003);
        assertEq(result.amdSevSnpPlatformInfo, 0x21);
        assertEq(result.amdSevSnpCpuid, 0x191101);
    }

    function test_snp_rejects_non_exact_report_length() public {
        bytes memory report = new bytes(1183);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpReportLength.selector, 1183, 1184));
        _verifySnp(report);
    }

    function test_snp_rejects_unsupported_report_version() public {
        bytes memory report = _report();
        _setLeUint32(report, 0, 6);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.UnsupportedSnpReportVersion.selector, 6));
        _verifySnp(report);
    }

    function test_snp_rejects_version_two_without_signed_cpuid() public {
        bytes memory report = _report();
        _setLeUint32(report, 0, 2);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.UnsupportedSnpReportVersion.selector, 2));
        _verifySnp(report);
    }

    function test_snp_rejects_policy_without_reserved_one_bit() public {
        bytes memory report = _report();
        _setLeUint64(report, 8, 0);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpPolicy.selector, 0));
        _verifySnp(report);
    }

    function test_snp_rejects_policy_reserved_high_bit() public {
        bytes memory report = _report();
        uint64 policy = (uint64(1) << 17) | (uint64(1) << 26);
        _setLeUint64(report, 8, policy);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpPolicy.selector, policy));
        _verifySnp(report);
    }

    function test_snp_rejects_nonzero_vmpl() public {
        bytes memory report = _report();
        _setLeUint32(report, 0x30, 1);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.UnsupportedSnpVmpl.selector, 1));
        _verifySnp(report);
    }

    function test_snp_accepts_absent_report_id_ma_sentinels() public {
        _verifySnp(_report());

        bytes memory report = _report();
        for (uint256 i = 0; i < 32; i++) {
            report[0x160 + i] = bytes1(uint8(0xff));
        }
        _verifySnp(report);
    }

    function test_snp_rejects_uniform_non_sentinel_report_id_ma() public {
        bytes memory report = _report();
        for (uint256 i = 0; i < 32; i++) {
            report[0x160 + i] = bytes1(uint8(1));
        }

        vm.expectRevert(TeeVerifier.SnpMigrationAgentNotSupported.selector);
        _verifySnp(report);
    }

    function test_snp_rejects_mixed_report_id_ma() public {
        bytes memory report = _report();
        for (uint256 i = 0; i < 32; i++) {
            report[0x160 + i] = bytes1(uint8(0xff));
        }
        report[0x160] = bytes1(0);

        vm.expectRevert(TeeVerifier.SnpMigrationAgentNotSupported.selector);
        _verifySnp(report);
    }

    function test_snp_rejects_invalid_signature_and_signing_key_fields() public {
        bytes memory report = _report();
        _setLeUint32(report, 0x34, 0);
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpSignatureAlgorithm.selector, 0));
        _verifySnp(report);

        report = _report();
        _setLeUint32(report, 0x48, uint32(2) << 2);
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpKeySettings.selector, uint32(2) << 2));
        _verifySnp(report);

        report = _report();
        _setLeUint32(report, 0x48, 2);
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpKeySettings.selector, 2));
        _verifySnp(report);
    }

    function test_snp_rejects_reserved_tcb_platform_and_report_fields() public {
        bytes memory report = _report();
        report[0x3a] = bytes1(uint8(1));
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpTcb.selector, 0x38, uint64(1) << 16));
        _verifySnp(report);

        report = _report();
        _setLeUint64(report, 0x40, uint64(1) << 7);
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpPlatformInfo.selector, uint64(1) << 7));
        _verifySnp(report);

        report = _report();
        report[0x4c] = bytes1(uint8(1));
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpReservedField.selector, 0x4c));
        _verifySnp(report);

        report = _report();
        report[0x18b] = bytes1(uint8(1));
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpReservedField.selector, 0x18b));
        _verifySnp(report);
    }

    function test_snp_rejects_unsupported_cpuid() public {
        bytes memory report = _report();
        report[0x189] = bytes1(uint8(0x20));

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.UnsupportedSnpCpuid.selector, 0x192001));
        _verifySnp(report);
    }

    function test_snp_rejects_invalid_tcb_order_but_does_not_order_launch_tcb() public {
        bytes memory report = _report();
        _setRawTcb(report, 0x180, 5, 0, 0, 0);
        _setRawTcb(report, 0x1e0, 4, 0, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(TeeVerifier.InvalidSnpTcbOrder.selector, bytes32(uint256(5)), bytes32(uint256(4)))
        );
        _verifySnp(report);

        report = _report();
        _setRawTcb(report, 0x1f0, type(uint8).max, type(uint8).max, type(uint8).max, type(uint8).max);
        _verifySnp(report);
    }

    function test_snp_applies_version_aware_mitigation_vector_rules() public {
        bytes memory report = _report();
        report[0x1f8] = bytes1(uint8(1));
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpReservedField.selector, 0x1f8));
        _verifySnp(report);

        report = _report();
        _setLeUint32(report, 0, 5);
        _setLeUint64(report, 0x1f8, 0x0123_4567_89ab_cdef);
        _setLeUint64(report, 0x200, 0xfedc_ba98_7654_3210);
        TeeVerificationResult memory result = _verifySnp(report);
        assertEq(result.amdSevSnpReportVersion, 5);
        assertEq(result.amdSevSnpLaunchMitigationVector, 0x0123_4567_89ab_cdef);
        assertEq(result.amdSevSnpCurrentMitigationVector, 0xfedc_ba98_7654_3210);

        report[0x208] = bytes1(uint8(1));
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidSnpReservedField.selector, 0x208));
        _verifySnp(report);
    }

    function _setRawTcb(
        bytes memory report,
        uint256 offset,
        uint8 bootloader,
        uint8 tee,
        uint8 snpVersion,
        uint8 microcode
    ) private pure {
        report[offset] = bytes1(bootloader);
        report[offset + 1] = bytes1(tee);
        report[offset + 6] = bytes1(snpVersion);
        report[offset + 7] = bytes1(microcode);
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

    function _tdxReport(bytes memory quote) internal pure returns (TeeReport memory) {
        return
            TeeReport({
                verificationBackendType: VerificationBackendType.Solidity, teeType: TEEType.IntelTDX, data: quote
            });
    }

    function _td10Quote() internal pure returns (bytes memory quote) {
        quote = new bytes(48 + 584);
        quote[0] = bytes1(uint8(4));
        quote[4] = bytes1(uint8(0x81));
        quote[48 + 123] = bytes1(uint8(0x10)); // TD_ATTRIBUTES.SEPT_VE_DISABLE
    }

    function _td15Quote() internal pure returns (bytes memory quote) {
        quote = new bytes(48 + 6 + 648);
        quote[0] = bytes1(uint8(5));
        quote[4] = bytes1(uint8(0x81));
        quote[48] = bytes1(uint8(3)); // TD15 quote body type
        quote[50] = bytes1(uint8(0x88)); // 648, little-endian
        quote[51] = bytes1(uint8(0x02));
        quote[54 + 123] = bytes1(uint8(0x10)); // TD_ATTRIBUTES.SEPT_VE_DISABLE
    }

    function test_tdx_extracts_debug() public {
        bytes memory quote = _td10Quote();
        quote[48 + 120] = bytes1(uint8(1));

        TeeVerificationResult memory result = teeVerifier.verifyTeeReport(_tdxReport(quote));

        assertTrue(result.valid);
        assertEq(uint8(result.teeType), uint8(TEEType.IntelTDX));
        assertEq(result.enabledTeeAttributes, TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT);
        assertEq(result.intelTdxTcbStatusBit, 1);
        assertEq(result.amdSevSnpTcbValues, bytes32(0));
        assertEq(result.amdSevSnpPlatformInfo, 0);
        assertEq(result.amdSevSnpCpuid, 0);
        assertEq(result.amdSevSnpReportVersion, 0);
        assertEq(result.amdSevSnpLaunchMitigationVector, 0);
        assertEq(result.amdSevSnpCurrentMitigationVector, 0);
    }

    function test_tdx_rejects_invalid_reserved_attribute_bit() public {
        bytes memory quote = _td10Quote();
        quote[48 + 121] = bytes1(uint8(1));

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidTdxAttributes.selector, bytes8(0x0001001000000000)));
        teeVerifier.verifyTeeReport(_tdxReport(quote));
    }

    function test_tdx_requires_sept_ve_disable() public {
        bytes memory quote = _td10Quote();
        quote[48 + 123] = bytes1(0);

        vm.expectRevert(TeeVerifier.TdxSeptVeDisableRequired.selector);
        teeVerifier.verifyTeeReport(_tdxReport(quote));
    }

    function test_tdx_rejects_nonzero_mr_servicetd() public {
        bytes memory quote = _td15Quote();
        quote[54 + 600] = bytes1(uint8(1));

        vm.expectRevert(TeeVerifier.TdxMigrationServiceTdNotSupported.selector);
        teeVerifier.verifyTeeReport(_tdxReport(quote));
    }

    function test_tdx_returns_one_hot_configurable_tcb_statuses() public {
        bytes memory quote = _td10Quote();
        uint8[8] memory statuses = [uint8(0), 1, 2, 3, 4, 5, 8, 9];
        for (uint256 i = 0; i < statuses.length; i++) {
            dcap.setTcbStatus(statuses[i]);
            TeeVerificationResult memory result = teeVerifier.verifyTeeReport(_tdxReport(quote));
            assertEq(result.intelTdxTcbStatusBit, uint256(1) << statuses[i]);
        }
    }

    function test_tdx_rejects_revoked_unrecognized_and_unknown_tcb_statuses() public {
        bytes memory quote = _td10Quote();
        uint8[4] memory statuses = [uint8(6), 7, 10, type(uint8).max];
        for (uint256 i = 0; i < statuses.length; i++) {
            dcap.setTcbStatus(statuses[i]);
            vm.expectRevert(abi.encodeWithSelector(TeeVerifier.DcapTcbStatusNotAccepted.selector, statuses[i]));
            teeVerifier.verifyTeeReport(_tdxReport(quote));
        }
    }
}
