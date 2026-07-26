// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    TeeReport,
    TEEType,
    VerificationBackendType,
    ZkProof,
    SnpZkProof,
    TeeVerificationResult
} from "./types/Evidence.sol";
import {IDcapAttestation} from "./interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal, VerificationResult} from "./interfaces/external/ISnpAttestation.sol";
import {ITeeVerifier} from "./interfaces/ITeeVerifier.sol";
import {
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT,
    SNP_PLATFORM_INFO_SUPPORTED_MASK
} from "./types/Constants.sol";
import {AmdSnpPolicy} from "./lib/AmdSnpPolicy.sol";

/// @title TeeVerifier
/// @notice Standalone contract for verifying TEE attestation reports across multiple backends
/// @dev Dispatches verification to vendor-specific contracts (DCAP for Intel TDX, SNP for AMD SEV-SNP)
///      and extracts reportData from the verified output. Designed to be referenced externally.
contract TeeVerifier is ITeeVerifier {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Version
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Contract version
    string public constant TEE_VERIFIER_VERSION = "1.3.0";

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables - Vendor-Specific Attestation Contracts
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice DCAP attestation verifier contract for Intel TDX quotes
    IDcapAttestation public immutable dcapAttestation;

    /// @notice SNP attestation verifier contract for AMD SEV-SNP reports
    ISnpAttestation public immutable snpAttestation;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants - DCAP Output Layout
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Quote body type identifier for TD10 (TDX 1.0) format
    uint16 private constant QUOTE_BODY_TYPE_TD10 = 2;

    /// @dev Quote body type identifier for TD15 (TDX 1.5) format
    uint16 private constant QUOTE_BODY_TYPE_TD15 = 3;

    /// @dev Size of TD10 quote body in bytes
    uint256 private constant TD10_QUOTE_BODY_SIZE = 584;

    /// @dev Size of TD15 quote body in bytes
    uint256 private constant TD15_QUOTE_BODY_SIZE = 648;

    /// @dev Offset of quote body in DCAP output (2+2+1+6 byte header)
    uint256 private constant DCAP_QUOTE_BODY_OFFSET = 11;

    /// @dev Offset of tcbStatus in DCAP output (2-byte version + 2-byte quoteBodyType)
    uint256 private constant DCAP_TCB_STATUS_OFFSET = 4;

    /// @dev DCAP TCB statuses 6 (Revoked), 7 (Unrecognized), and unknown values are hard failures.
    uint8 private constant TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED = 5;
    uint8 private constant TCB_STATUS_RELAUNCH_ADVISED = 8;
    uint8 private constant TCB_STATUS_RELAUNCH_ADVISED_CONFIGURATION_NEEDED = 9;

    /// @dev Size of reportData field in bytes
    uint256 private constant REPORT_DATA_SIZE = 64;

    /// @dev Offset of tdAttributes within TD10/TD15 quote body
    uint256 private constant TD_ATTRIBUTES_OFFSET = 120;

    /// @dev TD_ATTRIBUTES.DEBUG is bit 0.
    uint8 private constant TD_ATTRIBUTES_DEBUG_MASK = 0x01;

    /// @dev TD_ATTRIBUTES.SEPT_VE_DISABLE is bit 28.
    uint8 private constant TD_ATTRIBUTES_SEPT_VE_DISABLE_MASK = 0x10;

    /// @dev Offset of MR_SERVICETD in a TD15 quote body.
    uint256 private constant TD15_MR_SERVICETD_OFFSET = 600;

    /// @dev Size of MR_SERVICETD.
    uint256 private constant TD15_MR_SERVICETD_SIZE = 48;

    /// @dev Offset of reportData within quote body
    uint256 private constant DCAP_REPORT_DATA_START = 520;

    /// @dev Minimum valid quote body length (must contain reportData)
    uint256 private constant DCAP_MIN_OUTPUT_LEN = 584; // TD10_QUOTE_BODY_SIZE (520 + 64)

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants - SNP Raw Report Layout
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Offset of REPORT_DATA in AMD SEV-SNP raw report (per AMD spec)
    uint256 private constant SNP_REPORT_DATA_OFFSET = 0x50; // 80 decimal

    /// @dev Required AMD SEV-SNP attestation report length.
    uint256 private constant SNP_REPORT_SIZE = 1184;

    uint256 private constant SNP_VERSION_OFFSET = 0x00;
    uint256 private constant SNP_POLICY_OFFSET = 0x08;
    uint256 private constant SNP_VMPL_OFFSET = 0x30;
    uint256 private constant SNP_SIGNATURE_ALGORITHM_OFFSET = 0x34;
    uint256 private constant SNP_CURRENT_TCB_OFFSET = 0x38;
    uint256 private constant SNP_PLATFORM_INFO_OFFSET = 0x40;
    uint256 private constant SNP_KEY_SETTINGS_OFFSET = 0x48;
    uint256 private constant SNP_RESERVED_1_OFFSET = 0x4c;
    uint256 private constant SNP_REPORTED_TCB_OFFSET = 0x180;
    uint256 private constant SNP_CPUID_OFFSET = 0x188;
    uint256 private constant SNP_CPUID_RESERVED_OFFSET = 0x18b;
    uint256 private constant SNP_CPUID_RESERVED_SIZE = 21;
    uint256 private constant SNP_COMMITTED_TCB_OFFSET = 0x1e0;
    uint256 private constant SNP_CURRENT_VERSION_RESERVED_OFFSET = 0x1eb;
    uint256 private constant SNP_COMMITTED_VERSION_RESERVED_OFFSET = 0x1ef;
    uint256 private constant SNP_LAUNCH_TCB_OFFSET = 0x1f0;
    uint256 private constant SNP_LAUNCH_MITIGATION_VECTOR_OFFSET = 0x1f8;
    uint256 private constant SNP_CURRENT_MITIGATION_VECTOR_END = 0x208;
    uint256 private constant SNP_SIGNATURE_OFFSET = 0x2a0;
    uint256 private constant SNP_REPORT_ID_MA_OFFSET = 0x160;
    uint256 private constant SNP_REPORT_ID_MA_SIZE = 32;
    uint32 private constant SNP_SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 = 1;
    uint64 private constant SNP_POLICY_RESERVED_ONE = uint64(1) << 17;
    uint64 private constant SNP_POLICY_MIGRATE_MA = uint64(1) << 18;
    uint64 private constant SNP_POLICY_DEBUG = uint64(1) << 19;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TEE type is not supported by this verifier
    error UnsupportedTeeType(TEEType actual);

    /// @notice Verification backend type is not supported for this TEE type
    error UnsupportedBackendType(TEEType teeType, VerificationBackendType backend);

    /// @notice TEE report bytes are shorter than the minimum required for the format being parsed
    error TeeReportTooShort(uint256 length, uint256 minRequired);

    /// @notice DCAP quote bodyType field is neither TD10 (2) nor TD15 (3)
    error UnsupportedDcapBodyType(uint16 bodyType);

    /// @notice DCAP report-data slice would read past the end of the quote body
    error DcapReportDataOob(uint256 length, uint256 minRequired);

    /// @notice The upstream DCAP verifier returned !success. The full output is included
    ///         so off-chain decoders can surface the underlying reason.
    error DcapVerificationFailed(bytes output);

    /// @notice The DCAP verifier returned a hard-rejected or unknown trusted computing base status.
    error DcapTcbStatusNotAccepted(uint8 actual);

    /// @notice Reserved Intel TDX TD_ATTRIBUTES bits are set.
    error InvalidTdxAttributes(bytes8 actual);

    /// @notice Intel TDX TD_ATTRIBUTES.SEPT_VE_DISABLE is not set.
    error TdxSeptVeDisableRequired();

    /// @notice Intel TDX 1.5 MR_SERVICETD is nonzero.
    error TdxMigrationServiceTdNotSupported();

    /// @notice The upstream SNP verifier returned a non-Success VerificationResult.
    error SnpVerificationFailed(VerificationResult result);

    /// @notice The supplied SNP raw report does not hash to the journal's reportHash.
    ///         Indicates the report body was not the one the ZK proof attested to.
    error SnpReportHashMismatch(bytes32 expected, bytes32 actual);

    /// @notice The AMD SEV-SNP raw report is not exactly 1,184 bytes.
    error InvalidSnpReportLength(uint256 actual, uint256 expected);

    /// @notice The AMD SEV-SNP report version is not supported.
    error UnsupportedSnpReportVersion(uint32 actual);

    /// @notice Reserved AMD SEV-SNP POLICY bits have invalid values.
    error InvalidSnpPolicy(uint64 actual);

    /// @notice AMD SEV-SNP reports must be requested at VMPL 0.
    error UnsupportedSnpVmpl(uint32 actual);

    /// @notice AMD SEV-SNP REPORT_ID_MA is not a supported no-association sentinel.
    error SnpMigrationAgentNotSupported();

    /// @notice The AMD SEV-SNP report uses an unsupported signature algorithm.
    error InvalidSnpSignatureAlgorithm(uint32 actual);

    /// @notice The AMD SEV-SNP report uses invalid signing-key settings.
    error InvalidSnpKeySettings(uint32 actual);

    /// @notice An AMD SEV-SNP field that must be zero contains nonzero bytes.
    error InvalidSnpReservedField(uint256 offset);

    /// @notice An AMD SEV-SNP TCB value has nonzero reserved or unsupported fields.
    error InvalidSnpTcb(uint256 offset, uint64 actual);

    /// @notice The AMD SEV-SNP PLATFORM_INFO field contains unsupported bits.
    error InvalidSnpPlatformInfo(uint64 actual);

    /// @notice The AMD SEV-SNP CPUID does not identify a supported Milan or Genoa processor.
    error UnsupportedSnpCpuid(uint24 actual);

    /// @notice The signed AMD SEV-SNP TCB values have an invalid security-version order.
    error InvalidSnpTcbOrder(bytes32 lower, bytes32 upper);

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Initializes the TeeVerifier with vendor-specific attestation contracts
    /// @param _dcapAttestation Address of the DCAP attestation verifier contract
    /// @param _snpAttestation Address of the SNP attestation verifier contract
    constructor(IDcapAttestation _dcapAttestation, ISnpAttestation _snpAttestation) {
        dcapAttestation = _dcapAttestation;
        snpAttestation = _snpAttestation;
    }

    function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32) {
        if (teeReport.verificationBackendType == VerificationBackendType.Solidity) {
            return keccak256(teeReport.data);
        } else {
            ZkProof memory zkProof = abi.decode(teeReport.data, (ZkProof));
            bytes memory zkOutput = zkProof.output;
            if (zkOutput.length < 32) revert TeeReportTooShort(zkOutput.length, 32);
            // get the last 32 bytes of the output
            bytes32 outputHash;
            assembly ("memory-safe") {
                let outputLen := mload(zkOutput)
                outputHash := mload(add(zkOutput, add(0x20, sub(outputLen, 32))))
            }
            return outputHash;
        }
    }

    /// @notice Verifies a TEE attestation report
    /// @param teeReport The TEE attestation report to verify (contains backend type, TEE type, and data)
    /// @return result Verification result containing validity status, report data, and TEE type
    function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory result) {
        if (teeReport.teeType == TEEType.IntelTDX) {
            return _verifyIntelTdx(teeReport);
        } else if (teeReport.teeType == TEEType.AmdSevSnp) {
            return _verifyAmdSevSnp(teeReport);
        } else {
            revert UnsupportedTeeType(teeReport.teeType);
        }
    }

    /// @dev Extracts the full quote body from DCAP packed output bytes
    /// @param output The DCAP verifier output (abi.encodePacked format)
    /// @return quoteBody The extracted TD10 (584 bytes) or TD15 (648 bytes) quote body
    function extractDcapQuoteBody(bytes memory output) private pure returns (bytes memory quoteBody) {
        // Validate minimum length to read quoteBodyType
        if (output.length < 4) {
            revert TeeReportTooShort(output.length, 4);
        }

        // Read quoteBodyType (uint16 BE) from bytes [2:4]
        uint16 quoteBodyType;
        assembly ("memory-safe") {
            // Load word containing bytes [0:32]
            let word := mload(add(output, 0x20))
            // Shift right 224 bits (28 bytes) to align bytes [2:4] to low position, mask to 16 bits
            quoteBodyType := and(shr(224, word), 0xFFFF)
        }

        // Determine body size based on quote type
        uint256 bodySize;
        if (quoteBodyType == QUOTE_BODY_TYPE_TD10) {
            bodySize = TD10_QUOTE_BODY_SIZE;
        } else if (quoteBodyType == QUOTE_BODY_TYPE_TD15) {
            bodySize = TD15_QUOTE_BODY_SIZE;
        } else {
            revert UnsupportedDcapBodyType(quoteBodyType);
        }

        // Validate output length
        if (output.length < DCAP_QUOTE_BODY_OFFSET + bodySize) {
            revert TeeReportTooShort(output.length, DCAP_QUOTE_BODY_OFFSET + bodySize);
        }

        // Allocate quote body buffer
        quoteBody = new bytes(bodySize);

        // Copy quote body from output[11:11+bodySize] using assembly
        assembly ("memory-safe") {
            let src := add(add(output, 0x20), DCAP_QUOTE_BODY_OFFSET)
            let dst := add(quoteBody, 0x20)

            // Copy in 32-byte chunks (ceiling division to handle non-aligned sizes)
            let chunks := div(add(bodySize, 31), 32)
            for { let i := 0 } lt(i, chunks) { i := add(i, 1) } {
                let offset := mul(i, 32)
                mstore(add(dst, offset), mload(add(src, offset)))
            }
        }
    }

    /// @dev Extracts the 64-byte reportData from a DCAP quote body
    /// @param quoteBody The TD10 or TD15 quote body (output of extractDcapQuoteBody)
    /// @return reportData The extracted 64-byte reportData field at offset 520
    function extractDcapReportData(bytes memory quoteBody) external pure returns (bytes memory reportData) {
        // Validate minimum length to contain reportData
        if (quoteBody.length < DCAP_MIN_OUTPUT_LEN) {
            revert DcapReportDataOob(quoteBody.length, DCAP_MIN_OUTPUT_LEN);
        }

        // Allocate reportData buffer
        reportData = new bytes(REPORT_DATA_SIZE);

        // Copy reportData from quoteBody[520:584] using assembly
        assembly ("memory-safe") {
            let src := add(add(quoteBody, 0x20), DCAP_REPORT_DATA_START)
            let dst := add(reportData, 0x20)
            // Copy first 32 bytes
            mstore(dst, mload(src))
            // Copy remaining 32 bytes
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }
    }

    function _validateTdxReport(bytes memory quoteBody) private pure returns (bool debugEnabled) {
        bytes8 attributes;
        assembly ("memory-safe") {
            attributes := mload(add(add(quoteBody, 0x20), TD_ATTRIBUTES_OFFSET))
        }

        if (
            (uint8(quoteBody[TD_ATTRIBUTES_OFFSET]) & ~TD_ATTRIBUTES_DEBUG_MASK) != 0
                || uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 1]) != 0 || uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 2]) != 0
                || (uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 3]) & 0x2f) != 0
                || uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 4]) != 0 || uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 5]) != 0
                || uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 6]) != 0
                || (uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 7]) & 0x7f) != 0
        ) {
            revert InvalidTdxAttributes(attributes);
        }
        if ((uint8(quoteBody[TD_ATTRIBUTES_OFFSET + 3]) & TD_ATTRIBUTES_SEPT_VE_DISABLE_MASK) == 0) {
            revert TdxSeptVeDisableRequired();
        }
        if (
            quoteBody.length == TD15_QUOTE_BODY_SIZE
                && _hasNonzeroBytes(quoteBody, TD15_MR_SERVICETD_OFFSET, TD15_MR_SERVICETD_SIZE)
        ) {
            revert TdxMigrationServiceTdNotSupported();
        }
        return (uint8(quoteBody[TD_ATTRIBUTES_OFFSET]) & TD_ATTRIBUTES_DEBUG_MASK) != 0;
    }

    function _hasNonzeroBytes(bytes memory data, uint256 offset, uint256 length) private pure returns (bool) {
        for (uint256 i = 0; i < length; i++) {
            if (data[offset + i] != bytes1(0)) return true;
        }
        return false;
    }

    function _isAbsentSnpReportIdMa(bytes memory report) private pure returns (bool) {
        bool allZero = true;
        bool allOnes = true;
        for (uint256 i = 0; i < SNP_REPORT_ID_MA_SIZE; i++) {
            bytes1 value = report[SNP_REPORT_ID_MA_OFFSET + i];
            if (value != bytes1(0)) allZero = false;
            if (value != bytes1(0xff)) allOnes = false;
            if (!allZero && !allOnes) return false;
        }
        return true;
    }

    function _readLeUint32(bytes memory data, uint256 offset) private pure returns (uint32 value) {
        return uint32(uint8(data[offset])) | (uint32(uint8(data[offset + 1])) << 8)
            | (uint32(uint8(data[offset + 2])) << 16) | (uint32(uint8(data[offset + 3])) << 24);
    }

    function _readLeUint64(bytes memory data, uint256 offset) private pure returns (uint64 value) {
        value = uint64(uint8(data[offset])) | (uint64(uint8(data[offset + 1])) << 8)
            | (uint64(uint8(data[offset + 2])) << 16) | (uint64(uint8(data[offset + 3])) << 24)
            | (uint64(uint8(data[offset + 4])) << 32) | (uint64(uint8(data[offset + 5])) << 40)
            | (uint64(uint8(data[offset + 6])) << 48) | (uint64(uint8(data[offset + 7])) << 56);
    }

    function _normalizeSnpTcb(bytes memory report, uint256 offset) private pure returns (uint64 normalized) {
        uint64 raw = _readLeUint64(report, offset);
        if (
            uint8(report[offset + 2]) != 0 || uint8(report[offset + 3]) != 0 || uint8(report[offset + 4]) != 0
                || uint8(report[offset + 5]) != 0
        ) {
            revert InvalidSnpTcb(offset, raw);
        }
        normalized = uint64(uint8(report[offset])) | (uint64(uint8(report[offset + 1])) << 8)
            | (uint64(uint8(report[offset + 6])) << 16) | (uint64(uint8(report[offset + 7])) << 24);
    }

    function _extractSnpSecurityState(bytes memory report, uint32 version)
        private
        pure
        returns (bytes32 tcbValues, uint64 platformInfo, uint24 cpuid)
    {
        uint32 signatureAlgorithm = _readLeUint32(report, SNP_SIGNATURE_ALGORITHM_OFFSET);
        if (signatureAlgorithm != SNP_SIGNATURE_ALGORITHM_ECDSA_P384_SHA384) {
            revert InvalidSnpSignatureAlgorithm(signatureAlgorithm);
        }

        uint32 keySettings = _readLeUint32(report, SNP_KEY_SETTINGS_OFFSET);
        uint32 signingKey = (keySettings >> 2) & 7;
        if ((keySettings >> 5) != 0 || signingKey > 1 || (keySettings & 2) != 0) {
            revert InvalidSnpKeySettings(keySettings);
        }
        if (_hasNonzeroBytes(report, SNP_RESERVED_1_OFFSET, 4)) {
            revert InvalidSnpReservedField(SNP_RESERVED_1_OFFSET);
        }

        platformInfo = _readLeUint64(report, SNP_PLATFORM_INFO_OFFSET);
        if ((platformInfo & ~SNP_PLATFORM_INFO_SUPPORTED_MASK) != 0) {
            revert InvalidSnpPlatformInfo(platformInfo);
        }

        uint8 family = uint8(report[SNP_CPUID_OFFSET]);
        uint8 model = uint8(report[SNP_CPUID_OFFSET + 1]);
        uint8 stepping = uint8(report[SNP_CPUID_OFFSET + 2]);
        cpuid = (uint24(family) << 16) | (uint24(model) << 8) | uint24(stepping);
        if (family != 0x19 || model > 0x1f) {
            revert UnsupportedSnpCpuid(cpuid);
        }
        if (_hasNonzeroBytes(report, SNP_CPUID_RESERVED_OFFSET, SNP_CPUID_RESERVED_SIZE)) {
            revert InvalidSnpReservedField(SNP_CPUID_RESERVED_OFFSET);
        }
        if (
            report[SNP_CURRENT_VERSION_RESERVED_OFFSET] != bytes1(0)
                || report[SNP_COMMITTED_VERSION_RESERVED_OFFSET] != bytes1(0)
        ) {
            revert InvalidSnpReservedField(report[SNP_CURRENT_VERSION_RESERVED_OFFSET] != bytes1(0)
                    ? SNP_CURRENT_VERSION_RESERVED_OFFSET
                    : SNP_COMMITTED_VERSION_RESERVED_OFFSET);
        }

        uint64 currentTcb = _normalizeSnpTcb(report, SNP_CURRENT_TCB_OFFSET);
        uint64 reportedTcb = _normalizeSnpTcb(report, SNP_REPORTED_TCB_OFFSET);
        uint64 committedTcb = _normalizeSnpTcb(report, SNP_COMMITTED_TCB_OFFSET);
        uint64 launchTcb = _normalizeSnpTcb(report, SNP_LAUNCH_TCB_OFFSET);
        if (!AmdSnpPolicy.tcbMeetsMinimum(bytes32(uint256(committedTcb)), bytes32(uint256(reportedTcb)))) {
            revert InvalidSnpTcbOrder(bytes32(uint256(reportedTcb)), bytes32(uint256(committedTcb)));
        }
        if (!AmdSnpPolicy.tcbMeetsMinimum(bytes32(uint256(currentTcb)), bytes32(uint256(committedTcb)))) {
            revert InvalidSnpTcbOrder(bytes32(uint256(committedTcb)), bytes32(uint256(currentTcb)));
        }
        tcbValues = bytes32(
            (uint256(currentTcb) << 192) | (uint256(reportedTcb) << 128) | (uint256(committedTcb) << 64)
                | uint256(launchTcb)
        );

        uint256 reservedOffset = version < 5 ? SNP_LAUNCH_MITIGATION_VECTOR_OFFSET : SNP_CURRENT_MITIGATION_VECTOR_END;
        if (_hasNonzeroBytes(report, reservedOffset, SNP_SIGNATURE_OFFSET - reservedOffset)) {
            revert InvalidSnpReservedField(reservedOffset);
        }
    }

    /// @dev Extracts the full SNP attestation report from journal
    /// @param rawReport The SNP raw report bytes from VerifierJournal (already the full report)
    /// @return attestationReport The attestation report (validated and returned directly)
    function extractSnpAttestationReport(bytes memory rawReport) private pure returns (bytes memory attestationReport) {
        if (rawReport.length != SNP_REPORT_SIZE) {
            revert InvalidSnpReportLength(rawReport.length, SNP_REPORT_SIZE);
        }

        // rawReport IS the attestation report - return directly (no copy needed)
        return rawReport;
    }

    /// @dev Extracts reportData from SNP raw report bytes
    /// @param rawReport The SNP raw report bytes from VerifierJournal
    /// @return reportData The extracted 64-byte REPORT_DATA field
    function extractSnpReportData(bytes memory rawReport) external pure returns (bytes memory reportData) {
        if (rawReport.length != SNP_REPORT_SIZE) {
            revert InvalidSnpReportLength(rawReport.length, SNP_REPORT_SIZE);
        }

        // Allocate reportData buffer
        reportData = new bytes(REPORT_DATA_SIZE);

        // Copy reportData from rawReport[0x50:0x90] using assembly
        assembly ("memory-safe") {
            let src := add(add(rawReport, 0x20), SNP_REPORT_DATA_OFFSET)
            let dst := add(reportData, 0x20)
            // Copy first 32 bytes
            mstore(dst, mload(src))
            // Copy remaining 32 bytes
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Verification Dispatch
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies an Intel TDX attestation report using DCAP
    /// @param teeReport The TEE report containing Intel TDX quote data
    /// @return result Verification result with extracted reportData
    function _verifyIntelTdx(TeeReport memory teeReport) private returns (TeeVerificationResult memory result) {
        bool success;
        bytes memory output;

        if (teeReport.verificationBackendType == VerificationBackendType.Solidity) {
            // Direct on-chain verification
            (success, output) = dcapAttestation.verifyAndAttestOnChain(teeReport.data);
        } else {
            // ZK proof verification
            ZkProof memory zkProof = abi.decode(teeReport.data, (ZkProof));

            // Cast backend type to ZK coprocessor type (ordinals align after reordering)
            IDcapAttestation.ZkCoProcessorType zkType =
                IDcapAttestation.ZkCoProcessorType(uint8(teeReport.verificationBackendType));

            (success, output) = dcapAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
        }

        // Surface DCAP failure with the verifier's raw output so off-chain decoders
        // can pick out the specific reason (was silently swallowed before).
        if (!success) {
            revert DcapVerificationFailed(output);
        }

        if (output.length <= DCAP_TCB_STATUS_OFFSET) {
            revert TeeReportTooShort(output.length, DCAP_TCB_STATUS_OFFSET + 1);
        }
        uint8 tcbStatus = uint8(output[DCAP_TCB_STATUS_OFFSET]);
        if (
            tcbStatus > TCB_STATUS_RELAUNCH_ADVISED_CONFIGURATION_NEEDED
                || (tcbStatus > TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED && tcbStatus < TCB_STATUS_RELAUNCH_ADVISED)
        ) {
            revert DcapTcbStatusNotAccepted(tcbStatus);
        }
        uint256 tcbStatusBit = uint256(1) << tcbStatus;

        bytes memory quoteBody = extractDcapQuoteBody(output);
        bool debugEnabled = _validateTdxReport(quoteBody);
        uint256 enabledTeeAttributes = debugEnabled ? TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT : 0;

        return TeeVerificationResult({
            valid: true,
            reportData: quoteBody,
            teeType: TEEType.IntelTDX,
            enabledTeeAttributes: enabledTeeAttributes,
            intelTdxTcbStatusBit: tcbStatusBit,
            amdSevSnpTcbValues: bytes32(0),
            amdSevSnpPlatformInfo: 0,
            amdSevSnpCpuid: 0
        });
    }

    /// @dev Verifies an AMD SEV-SNP attestation report
    /// @param teeReport The TEE report containing SEV-SNP report data
    /// @return result Verification result with extracted reportData
    function _verifyAmdSevSnp(TeeReport memory teeReport) private returns (TeeVerificationResult memory result) {
        // SNP does not support Solidity backend (no on-chain verifier exists)
        if (teeReport.verificationBackendType == VerificationBackendType.Solidity) {
            revert UnsupportedBackendType(TEEType.AmdSevSnp, teeReport.verificationBackendType);
        }

        // ZK proof verification. The SNP journal commits only to keccak256(report), so the full
        // report body is carried separately in SnpZkProof.rawReport and bound to the proof below.
        SnpZkProof memory zkProof = abi.decode(teeReport.data, (SnpZkProof));

        // Cast backend type to ZK coprocessor type (ordinals align after reordering)
        ISnpAttestation.ZkCoProcessorType zkType =
            ISnpAttestation.ZkCoProcessorType(uint8(teeReport.verificationBackendType));

        VerifierJournal memory journal =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);

        // Surface SNP verifier failure mode (was silently swallowed before).
        if (journal.result != VerificationResult.Success) {
            revert SnpVerificationFailed(journal.result);
        }

        // Bind the supplied raw report to the proof. The journal only attests keccak256(report),
        // so without this check a valid proof could be paired with a forged report body.
        bytes32 computedHash = keccak256(zkProof.rawReport);
        if (computedHash != journal.reportHash) {
            revert SnpReportHashMismatch(journal.reportHash, computedHash);
        }

        bytes memory attestationReport = extractSnpAttestationReport(zkProof.rawReport);
        uint32 version = _readLeUint32(attestationReport, SNP_VERSION_OFFSET);
        if (version < 3 || version > 5) {
            revert UnsupportedSnpReportVersion(version);
        }

        uint64 policy = _readLeUint64(attestationReport, SNP_POLICY_OFFSET);
        if ((policy & SNP_POLICY_RESERVED_ONE) == 0 || (policy >> 26) != 0) {
            revert InvalidSnpPolicy(policy);
        }

        uint32 vmpl = _readLeUint32(attestationReport, SNP_VMPL_OFFSET);
        if (vmpl != 0) {
            revert UnsupportedSnpVmpl(vmpl);
        }
        if (!_isAbsentSnpReportIdMa(attestationReport)) {
            revert SnpMigrationAgentNotSupported();
        }
        (bytes32 tcbValues, uint64 platformInfo, uint24 cpuid) = _extractSnpSecurityState(attestationReport, version);

        uint256 enabledTeeAttributes;
        if ((policy & SNP_POLICY_DEBUG) != 0) {
            enabledTeeAttributes |= TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT;
        }
        if ((policy & SNP_POLICY_MIGRATE_MA) != 0) {
            enabledTeeAttributes |= TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT;
        }

        return TeeVerificationResult({
            valid: true,
            reportData: attestationReport,
            teeType: TEEType.AmdSevSnp,
            enabledTeeAttributes: enabledTeeAttributes,
            intelTdxTcbStatusBit: 0,
            amdSevSnpTcbValues: tcbValues,
            amdSevSnpPlatformInfo: platformInfo,
            amdSevSnpCpuid: cpuid
        });
    }
}
