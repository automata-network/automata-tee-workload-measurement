// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TeeReport, TEEType, VerificationBackendType, ZkProof, TeeVerificationResult} from "./types/Evidence.sol";
import {IDcapAttestation} from "./interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal, VerificationResult} from "./interfaces/external/ISnpAttestation.sol";
import {ITeeVerifier} from "./interfaces/ITeeVerifier.sol";

/// @title TeeVerifier
/// @notice Standalone contract for verifying TEE attestation reports across multiple backends
/// @dev Dispatches verification to vendor-specific contracts (DCAP for Intel TDX, SNP for AMD SEV-SNP)
///      and extracts reportData from the verified output. Designed to be referenced externally.
contract TeeVerifier is ITeeVerifier {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Version
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Contract version
    string public constant TEE_VERIFIER_VERSION = "1.0.0";

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

    /// @dev Size of reportData field in bytes
    uint256 private constant REPORT_DATA_SIZE = 64;

    /// @dev Offset of reportData within quote body
    uint256 private constant DCAP_REPORT_DATA_START = 520;

    /// @dev Minimum valid quote body length (must contain reportData)
    uint256 private constant DCAP_MIN_OUTPUT_LEN = 584; // TD10_QUOTE_BODY_SIZE (520 + 64)

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants - SNP Raw Report Layout
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Offset of REPORT_DATA in AMD SEV-SNP raw report (per AMD spec)
    uint256 private constant SNP_REPORT_DATA_OFFSET = 0x50; // 80 decimal

    /// @dev Minimum valid SNP report length (must contain REPORT_DATA)
    uint256 private constant SNP_MIN_REPORT_LEN = 144; // 80 + 64

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

    /// @notice SNP raw report bytes are shorter than the minimum required to contain REPORT_DATA
    error SnpReportTooShort(uint256 length, uint256 minRequired);

    /// @notice The upstream DCAP verifier returned !success. The full output is included
    ///         so off-chain decoders can surface the underlying reason.
    error DcapVerificationFailed(bytes output);

    /// @notice The upstream SNP verifier returned a non-Success VerificationResult.
    error SnpVerificationFailed(VerificationResult result);

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

    /// @dev Extracts the full SNP attestation report from journal
    /// @param rawReport The SNP raw report bytes from VerifierJournal (already the full report)
    /// @return attestationReport The attestation report (validated and returned directly)
    function extractSnpAttestationReport(bytes memory rawReport) private pure returns (bytes memory attestationReport) {
        // Validate minimum length
        if (rawReport.length < SNP_MIN_REPORT_LEN) {
            revert SnpReportTooShort(rawReport.length, SNP_MIN_REPORT_LEN);
        }

        // rawReport IS the attestation report - return directly (no copy needed)
        return rawReport;
    }

    /// @dev Extracts reportData from SNP raw report bytes
    /// @param rawReport The SNP raw report bytes from VerifierJournal
    /// @return reportData The extracted 64-byte REPORT_DATA field
    function extractSnpReportData(bytes memory rawReport) external pure returns (bytes memory reportData) {
        // Validate minimum length to contain REPORT_DATA
        if (rawReport.length < SNP_MIN_REPORT_LEN) {
            revert SnpReportTooShort(rawReport.length, SNP_MIN_REPORT_LEN);
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

        // Extract quote body from DCAP output (Step 1)
        bytes memory quoteBody = extractDcapQuoteBody(output);

        return TeeVerificationResult({valid: true, reportData: quoteBody, teeType: TEEType.IntelTDX});
    }

    /// @dev Verifies an AMD SEV-SNP attestation report
    /// @param teeReport The TEE report containing SEV-SNP report data
    /// @return result Verification result with extracted reportData
    function _verifyAmdSevSnp(TeeReport memory teeReport) private returns (TeeVerificationResult memory result) {
        // SNP does not support Solidity backend (no on-chain verifier exists)
        if (teeReport.verificationBackendType == VerificationBackendType.Solidity) {
            revert UnsupportedBackendType(TEEType.AmdSevSnp, teeReport.verificationBackendType);
        }

        // ZK proof verification
        ZkProof memory zkProof = abi.decode(teeReport.data, (ZkProof));

        // Cast backend type to ZK coprocessor type (ordinals align after reordering)
        ISnpAttestation.ZkCoProcessorType zkType =
            ISnpAttestation.ZkCoProcessorType(uint8(teeReport.verificationBackendType));

        VerifierJournal memory journal =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);

        // Surface SNP verifier failure mode (was silently swallowed before).
        if (journal.result != VerificationResult.Success) {
            revert SnpVerificationFailed(journal.result);
        }

        // Extract attestation report from SNP journal (Step 1)
        bytes memory attestationReport = extractSnpAttestationReport(journal.rawReport);

        return TeeVerificationResult({valid: true, reportData: attestationReport, teeType: TEEType.AmdSevSnp});
    }
}
