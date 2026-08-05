// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TeeReport, TeeVerificationResult} from "../types/Evidence.sol";

/// @title ITeeVerifier
/// @notice Interface for verifying TEE attestation reports across multiple backends
/// @dev Exposes verification methods and report data extraction utilities
interface ITeeVerifier {
    /// @notice Verifies a TEE attestation report
    /// @param teeReport The TEE attestation report to verify (contains backend type, TEE type, and data)
    /// @return result Verification result containing validity, report data,
    ///         verified TEE type, and report-bound security-policy fields
    function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory result);

    function deriveGcpPcr15ExtendValue(TeeVerificationResult memory result) external pure returns (bytes32 extendValue);

    /// @notice Extracts the 64-byte reportData from a DCAP quote body
    /// @param quoteBody The TD10 or TD15 quote body (output of TEE verification)
    /// @return reportData The extracted 64-byte reportData field at offset 520
    function extractDcapReportData(bytes memory quoteBody) external pure returns (bytes memory reportData);

    /// @notice Extracts reportData from SNP raw report bytes
    /// @param rawReport The SNP raw report bytes from VerifierJournal
    /// @return reportData The extracted 64-byte REPORT_DATA field
    function extractSnpReportData(bytes memory rawReport) external pure returns (bytes memory reportData);
}
