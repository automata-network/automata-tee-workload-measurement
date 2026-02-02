// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TeeReport, TEEType} from "../../types/Evidence.sol";

/// @notice Result of TEE attestation report verification
struct TeeVerificationResult {
    /// @dev True if the TEE report signature and structure are valid
    bool valid;
    /// @dev REPORT_DATA field extracted from the TEE report (binding nonce/commitment)
    bytes32 reportData;
    /// @dev TEE technology type (Intel TDX or AMD SEV-SNP)
    TEEType teeType;
}

/// @title ITeeVerifier
/// @notice Unified interface for verifying TEE attestation reports across all backends and TEE types
/// @dev Abstracts over raw vendor-specific interfaces (IDcapAttestation, ISnpAttestation)
///      and supports multiple verification backends (Solidity, ZK proofs)
interface ITeeVerifier {
    /// @notice Verifies a TEE attestation report
    /// @param teeReport The TEE attestation report to verify (contains backend type, TEE type, and data)
    /// @return result Verification result containing validity status, report data, and TEE type
    function verifyTeeReport(TeeReport calldata teeReport) external view returns (TeeVerificationResult memory result);
}
