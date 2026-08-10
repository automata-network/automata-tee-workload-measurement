// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {ISnpAttestation, VerificationResult} from "../src/interfaces/external/ISnpAttestation.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {MockAutomataSnpAttestation} from "./mocks/MockAutomataSnpAttestation.sol";
import {MockAutomataDcapAttestation} from "./mocks/MockAutomataDcapAttestation.sol";
import {TeeReport, TEEType, VerificationBackendType, TeeVerificationResult} from "../src/types/Evidence.sol";
import {AmdSevSnpZkEvidence, IntelTdxDcapZkEvidence, ProgramBoundZkProof, ZkProofType} from "../src/types/Zk.sol";
import {AmdSevSnpZkVerifierAdapter, IntelTdxDcapZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {Bytes48, LibBytes} from "../src/lib/LibBytes.sol";
import {Sha2Ext} from "../src/lib/Sha2Ext.sol";
import {
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT
} from "../src/types/Constants.sol";

/// @notice Exercises the SEV-SNP path of TeeVerifier against the SDK journal layout
///         (VerifierJournal.reportHash = keccak256(report)), including the report-binding guard.
contract TeeVerifierSnpTest is Test {
    bytes32 internal constant SNP_PROGRAM_IDENTIFIER = keccak256("amd_sev_snp.v1.test");
    bytes32 internal constant TDX_PROGRAM_IDENTIFIER = keccak256("intel_tdx_dcap.v1.test");

    TeeVerifier internal teeVerifier;
    MockAutomataSnpAttestation internal snp;
    MockAutomataDcapAttestation internal dcap;

    function setUp() public {
        snp = new MockAutomataSnpAttestation();
        dcap = new MockAutomataDcapAttestation();
        ZkVerifierRegistry implementation = new ZkVerifierRegistry();
        ZkVerifierRegistry registry = ZkVerifierRegistry(
            address(
                new ERC1967Proxy(
                    address(implementation), abi.encodeCall(ZkVerifierRegistry.initialize, (address(this)))
                )
            )
        );
        AmdSevSnpZkVerifierAdapter adapter =
            new AmdSevSnpZkVerifierAdapter(ISnpAttestation(address(snp)), ISnpAttestation.ZkCoProcessorType.RiscZero);
        registry.setZkProgramConfig(
            ZkProofType.AmdSevSnp, VerificationBackendType.ZkRiscZero, SNP_PROGRAM_IDENTIFIER, address(adapter), true
        );
        IntelTdxDcapZkVerifierAdapter tdxAdapter = new IntelTdxDcapZkVerifierAdapter(
            IDcapAttestation(address(dcap)), IDcapAttestation.ZkCoProcessorType.Succinct, 19
        );
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap,
            VerificationBackendType.ZkSuccinct,
            TDX_PROGRAM_IDENTIFIER,
            address(tdxAdapter),
            true
        );
        teeVerifier = new TeeVerifier(IDcapAttestation(address(dcap)), IZkVerifierRegistry(address(registry)));
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
        AmdSevSnpZkEvidence memory evidence = AmdSevSnpZkEvidence({
            proof: ProgramBoundZkProof({
                programIdentifier: SNP_PROGRAM_IDENTIFIER, output: journalOutput, proofBytes: hex""
            }),
            rawReport: rawReport
        });
        return TeeReport({
            verificationBackendType: VerificationBackendType.ZkRiscZero,
            teeType: TEEType.AmdSevSnp,
            data: abi.encode(evidence)
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

    function test_gcp_snp_pcr15_extend_value_is_exact_report_id() public {
        bytes memory report = _report();
        bytes32 reportId = bytes32(uint256(0x1234));
        for (uint256 i; i < 32; ++i) {
            report[0x140 + i] = reportId[i];
        }
        TeeVerificationResult memory result = _verifySnp(report);

        assertEq(teeVerifier.deriveGcpPcr15ExtendValue(result), reportId);
    }

    function test_gcp_tdx_pcr15_extend_value_is_zero_padded_uuid() public view {
        bytes memory quoteBody = new bytes(584);
        bytes16 uuid = 0x00112233445566778899aabbccddeeff;
        for (uint256 i; i < 16; ++i) {
            quoteBody[520 + i] = uuid[i];
        }
        Bytes48 memory rtmr3 = Sha2Ext.sha384(abi.encodePacked(new bytes(48), new bytes(32), uuid));
        bytes memory encodedRtmr3 = LibBytes.toBytes(rtmr3);
        for (uint256 i; i < 48; ++i) {
            quoteBody[472 + i] = encodedRtmr3[i];
        }
        TeeVerificationResult memory result;
        result.valid = true;
        result.teeType = TEEType.IntelTDX;
        result.reportData = quoteBody;

        assertEq(teeVerifier.deriveGcpPcr15ExtendValue(result), bytes32(uint256(uint128(uuid))));
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

    function test_snp_rejects_invalid_tcb_order() public {
        // REPORTED_TCB (0x180) must not exceed COMMITTED_TCB (0x1e0).
        bytes memory report = _report();
        _setRawTcb(report, 0x180, 5, 0, 0, 0);
        _setRawTcb(report, 0x1e0, 4, 0, 0, 0);
        vm.expectRevert(
            abi.encodeWithSelector(TeeVerifier.InvalidSnpTcbOrder.selector, bytes32(uint256(5)), bytes32(uint256(4)))
        );
        _verifySnp(report);

        // LAUNCH_TCB (0x1f0) is the COMMITTED_TCB captured at launch, so it must not exceed
        // the current COMMITTED_TCB either.
        report = _report();
        _setRawTcb(report, 0x1f0, type(uint8).max, type(uint8).max, type(uint8).max, type(uint8).max);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeVerifier.InvalidSnpTcbOrder.selector, bytes32(uint256(type(uint32).max)), bytes32(uint256(0))
            )
        );
        _verifySnp(report);

        // A LAUNCH_TCB at or below COMMITTED_TCB is accepted.
        report = _report();
        _setRawTcb(report, 0x38, 6, 0, 0, 0);
        _setRawTcb(report, 0x180, 4, 0, 0, 0);
        _setRawTcb(report, 0x1e0, 6, 0, 0, 0);
        _setRawTcb(report, 0x1f0, 5, 0, 0, 0);
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

    function _tdxReport(bytes memory quote) internal pure returns (TeeReport memory) {
        return
            TeeReport({
                verificationBackendType: VerificationBackendType.Solidity, teeType: TEEType.IntelTDX, data: quote
            });
    }

    function _tdxQuoteBody(bytes memory quote, uint256 bodyOffset, uint256 bodyLength)
        internal
        pure
        returns (bytes memory body)
    {
        body = new bytes(bodyLength);
        for (uint256 i = 0; i < bodyLength; i++) {
            body[i] = quote[bodyOffset + i];
        }
    }

    function _tdxZkReport(bytes memory fullQuote, bytes memory quoteBody, uint16 quoteBodyType)
        internal
        pure
        returns (TeeReport memory)
    {
        uint16 quoteVersion = uint16(uint8(fullQuote[0])) | (uint16(uint8(fullQuote[1])) << 8);
        bytes memory compactOutput = abi.encodePacked(
            quoteVersion, quoteBodyType, uint8(0), bytes6(0x010203040506), keccak256(fullQuote), keccak256(quoteBody)
        );
        IntelTdxDcapZkEvidence memory evidence = IntelTdxDcapZkEvidence({
            proof: ProgramBoundZkProof({
                programIdentifier: TDX_PROGRAM_IDENTIFIER,
                output: abi.encodePacked(uint16(compactOutput.length), compactOutput),
                proofBytes: hex""
            }),
            quoteBody: quoteBody
        });
        return TeeReport({
            verificationBackendType: VerificationBackendType.ZkSuccinct,
            teeType: TEEType.IntelTDX,
            data: abi.encode(evidence)
        });
    }

    function _td10Quote() internal pure returns (bytes memory quote) {
        quote = new bytes(48 + 584 + 4);
        quote[0] = bytes1(uint8(4));
        quote[4] = bytes1(uint8(0x81));
        quote[48 + 123] = bytes1(uint8(0x10)); // TD_ATTRIBUTES.SEPT_VE_DISABLE
    }

    function _td15Quote() internal pure returns (bytes memory quote) {
        quote = new bytes(48 + 6 + 648 + 4);
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

    function test_tdx_solidity_and_zk_return_the_same_full_quote_hash() public {
        bytes memory quote = _td10Quote();
        bytes memory quoteBody = _tdxQuoteBody(quote, 48, 584);

        TeeVerificationResult memory solidityResult = teeVerifier.verifyTeeReport(_tdxReport(quote));
        TeeVerificationResult memory zkResult = teeVerifier.verifyTeeReport(_tdxZkReport(quote, quoteBody, 2));

        assertEq(solidityResult.teeReportBytesHash, keccak256(quote));
        assertEq(zkResult.teeReportBytesHash, keccak256(quote));
        assertEq(solidityResult.teeReportBytesHash, zkResult.teeReportBytesHash);
        assertEq(solidityResult.reportData, quoteBody);
        assertEq(zkResult.reportData, quoteBody);
    }

    function test_tdx_td15_solidity_and_zk_return_the_same_full_quote_hash() public {
        bytes memory quote = _td15Quote();
        bytes memory quoteBody = _tdxQuoteBody(quote, 54, 648);

        TeeVerificationResult memory solidityResult = teeVerifier.verifyTeeReport(_tdxReport(quote));
        TeeVerificationResult memory zkResult = teeVerifier.verifyTeeReport(_tdxZkReport(quote, quoteBody, 3));

        assertEq(solidityResult.teeReportBytesHash, keccak256(quote));
        assertEq(zkResult.teeReportBytesHash, keccak256(quote));
        assertEq(solidityResult.teeReportBytesHash, zkResult.teeReportBytesHash);
        assertEq(solidityResult.reportData, quoteBody);
        assertEq(zkResult.reportData, quoteBody);
    }

    function test_tdx_solidity_rejects_all_trailing_bytes() public {
        bytes memory exactQuote = _td10Quote();
        for (uint256 trailingByte = 0; trailingByte <= 1; trailingByte++) {
            bytes memory paddedQuote = bytes.concat(exactQuote, bytes1(uint8(trailingByte)));
            vm.expectRevert(
                abi.encodeWithSelector(
                    TeeVerifier.InvalidDcapQuoteLength.selector, paddedQuote.length, exactQuote.length
                )
            );
            teeVerifier.verifyTeeReport(_tdxReport(paddedQuote));
        }
    }

    function test_tdx_solidity_rejects_a_truncated_declared_signature() public {
        bytes memory quote = _td10Quote();
        _setLeUint32(quote, 48 + 584, 1);

        vm.expectRevert(
            abi.encodeWithSelector(TeeVerifier.InvalidDcapQuoteLength.selector, quote.length, quote.length + 1)
        );
        teeVerifier.verifyTeeReport(_tdxReport(quote));
    }

    function test_tdx_zk_rejects_a_different_supplied_quote_body() public {
        bytes memory quote = _td10Quote();
        bytes memory committedQuoteBody = _tdxQuoteBody(quote, 48, 584);
        bytes32 committedQuoteBodyHash = keccak256(committedQuoteBody);
        TeeReport memory report = _tdxZkReport(quote, committedQuoteBody, 2);
        IntelTdxDcapZkEvidence memory evidence = abi.decode(report.data, (IntelTdxDcapZkEvidence));
        evidence.quoteBody[0] = bytes1(uint8(1));
        report.data = abi.encode(evidence);

        vm.expectRevert(
            abi.encodeWithSelector(
                TeeVerifier.DcapQuoteBodyHashMismatch.selector, committedQuoteBodyHash, keccak256(evidence.quoteBody)
            )
        );
        teeVerifier.verifyTeeReport(report);
    }

    function test_tdx_zk_rejects_a_non_exact_quote_body_length() public {
        bytes memory quote = _td10Quote();
        TeeReport memory report = _tdxZkReport(quote, new bytes(583), 2);

        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.InvalidDcapQuoteBodyLength.selector, 583, 584));
        teeVerifier.verifyTeeReport(report);
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
