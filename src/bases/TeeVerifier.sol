// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TeeReport, TEEType, VerificationBackendType, ZkProof} from "../types/Evidence.sol";
import {ITeeVerifier, TeeVerificationResult} from "../interfaces/verifiers/ITeeVerifier.sol";
import {IDcapAttestation} from "../interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal, VerificationResult} from "../interfaces/external/ISnpAttestation.sol";

/// @title TeeVerifier
/// @notice Abstract base contract for verifying TEE attestation reports across multiple backends
/// @dev Dispatches verification to vendor-specific contracts (DCAP for Intel TDX, SNP for AMD SEV-SNP)
///      and extracts reportData from the verified output. Designed to be inherited by SessionRegistry.
abstract contract TeeVerifier is ITeeVerifier {
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
    uint16 internal constant QUOTE_BODY_TYPE_TD10 = 2;

    /// @dev Quote body type identifier for TD15 (TDX 1.5) format
    uint16 internal constant QUOTE_BODY_TYPE_TD15 = 3;

    /// @dev Size of TD10 quote body in bytes
    uint256 internal constant TD10_QUOTE_BODY_SIZE = 584;

    /// @dev Size of TD15 quote body in bytes
    uint256 internal constant TD15_QUOTE_BODY_SIZE = 648;

    /// @dev Size of reportData field in bytes
    uint256 internal constant REPORT_DATA_SIZE = 64;

    /// @dev Absolute offset of reportData in DCAP output (11 + 520)
    uint256 internal constant DCAP_REPORT_DATA_START = 531; // 11 + 520

    /// @dev Minimum valid DCAP output length (must contain header + reportData)
    uint256 internal constant DCAP_MIN_OUTPUT_LEN = 595; // 531 + 64

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants - SNP Raw Report Layout
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Offset of REPORT_DATA in AMD SEV-SNP raw report (per AMD spec)
    uint256 internal constant SNP_REPORT_DATA_OFFSET = 0x50; // 80 decimal

    /// @dev Minimum valid SNP report length (must contain REPORT_DATA)
    uint256 internal constant SNP_MIN_REPORT_LEN = 144; // 80 + 64

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TEE type is not supported by this verifier
    error UnsupportedTeeType(TEEType teeType);

    /// @notice Verification backend type is not supported for this TEE type
    error UnsupportedBackendType(VerificationBackendType backendType);

    /// @notice DCAP output is malformed or too short
    error InvalidDcapOutput();

    /// @notice SNP raw report is malformed or too short
    error InvalidSnpReport();

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

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Public Interface
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Verifies a TEE attestation report
    /// @param teeReport The TEE attestation report to verify (contains backend type, TEE type, and data)
    /// @return result Verification result containing validity status, report data, and TEE type
    function verifyTeeReport(TeeReport calldata teeReport)
        public
        override
        returns (TeeVerificationResult memory result)
    {
        if (teeReport.teeType == TEEType.IntelTDX) {
            return _verifyIntelTdx(teeReport);
        } else if (teeReport.teeType == TEEType.AmdSevSnp) {
            return _verifyAmdSevSnp(teeReport);
        } else {
            revert UnsupportedTeeType(teeReport.teeType);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Verification Dispatch
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies an Intel TDX attestation report using DCAP
    /// @param teeReport The TEE report containing Intel TDX quote data
    /// @return result Verification result with extracted reportData
    function _verifyIntelTdx(TeeReport calldata teeReport) internal returns (TeeVerificationResult memory result) {
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

        // If verification failed, return invalid result
        if (!success) {
            return TeeVerificationResult({valid: false, reportData: "", teeType: TEEType.IntelTDX});
        }

        // Extract reportData from DCAP output
        bytes memory reportData = _extractDcapReportData(output);

        return TeeVerificationResult({valid: true, reportData: reportData, teeType: TEEType.IntelTDX});
    }

    /// @dev Verifies an AMD SEV-SNP attestation report
    /// @param teeReport The TEE report containing SEV-SNP report data
    /// @return result Verification result with extracted reportData
    function _verifyAmdSevSnp(TeeReport calldata teeReport) internal returns (TeeVerificationResult memory result) {
        // SNP does not support Solidity backend (no on-chain verifier exists)
        if (teeReport.verificationBackendType == VerificationBackendType.Solidity) {
            revert UnsupportedBackendType(teeReport.verificationBackendType);
        }

        // ZK proof verification
        ZkProof memory zkProof = abi.decode(teeReport.data, (ZkProof));

        // Cast backend type to ZK coprocessor type (ordinals align after reordering)
        ISnpAttestation.ZkCoProcessorType zkType =
            ISnpAttestation.ZkCoProcessorType(uint8(teeReport.verificationBackendType));

        VerifierJournal memory journal = snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);

        // If verification failed, return invalid result
        if (journal.result != VerificationResult.Success) {
            return TeeVerificationResult({valid: false, reportData: "", teeType: TEEType.AmdSevSnp});
        }

        // Extract reportData from SNP raw report
        bytes memory reportData = _extractSnpReportData(journal.rawReport);

        return TeeVerificationResult({valid: true, reportData: reportData, teeType: TEEType.AmdSevSnp});
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Report Data Extraction
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Extracts reportData from DCAP packed output bytes
    /// @param output The DCAP verifier output (abi.encodePacked format)
    /// @return reportData The extracted 64-byte reportData field
    function _extractDcapReportData(bytes memory output) internal pure returns (bytes memory reportData) {
        // Validate minimum length to read quoteBodyType
        if (output.length < 4) {
            revert InvalidDcapOutput();
        }

        // Read quoteBodyType (uint16 BE) from bytes [2:4]
        uint16 quoteBodyType;
        assembly ("memory-safe") {
            // Load word containing bytes [0:32], shift right to get uint16 at [2:4]
            let word := mload(add(output, 0x20))
            // Shift right 240 bits (30 bytes) to get the 2-byte value at offset 2
            quoteBodyType := shr(240, word)
        }

        // Validate quoteBodyType is TD10 or TD15
        if (quoteBodyType != QUOTE_BODY_TYPE_TD10 && quoteBodyType != QUOTE_BODY_TYPE_TD15) {
            revert InvalidDcapOutput();
        }

        // Validate minimum length to contain reportData
        if (output.length < DCAP_MIN_OUTPUT_LEN) {
            revert InvalidDcapOutput();
        }

        // Allocate reportData buffer
        reportData = new bytes(REPORT_DATA_SIZE);

        // Copy reportData from output[531:595] using assembly
        assembly ("memory-safe") {
            let src := add(add(output, 0x20), DCAP_REPORT_DATA_START)
            let dst := add(reportData, 0x20)
            // Copy first 32 bytes
            mstore(dst, mload(src))
            // Copy remaining 32 bytes
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }
    }

    /// @dev Extracts reportData from SNP raw report bytes
    /// @param rawReport The SNP raw report bytes from VerifierJournal
    /// @return reportData The extracted 64-byte REPORT_DATA field
    function _extractSnpReportData(bytes memory rawReport) internal pure returns (bytes memory reportData) {
        // Validate minimum length to contain REPORT_DATA
        if (rawReport.length < SNP_MIN_REPORT_LEN) {
            revert InvalidSnpReport();
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
}
