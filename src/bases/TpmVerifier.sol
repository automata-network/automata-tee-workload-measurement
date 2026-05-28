// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {
    TpmReport,
    TpmReportType,
    TpmQuoteReport,
    TpmCertifyReport,
    VerificationBackendType,
    PcrValue
} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";
import {LibKey} from "../lib/LibKey.sol";
import {TpmBase} from "./TpmBase.sol";

/// @notice Result of TPM Quote verification
struct TpmQuoteVerificationResult {
    /// @dev True if the TPM quote signature is valid and structure is well-formed
    bool valid;
    /// @dev PCR values extracted from the quote (with event logs for DYNAMIC verification)
    PcrValue[] pcrValues;
}

/// @notice Result of TPM Certify verification
struct TpmCertifyVerificationResult {
    /// @dev True if the TPM certify signature is valid and structure is well-formed
    bool valid;
    /// @dev Public identity of the certified key (extracted from TPMT_PUBLIC)
    PublicIdentity certifiedKey;
    /// @dev Fingerprint of the certified key (for session binding)
    bytes32 certifiedKeyFingerprint;
}

/// @title TpmVerifier
/// @notice Abstract base contract for verifying TPM quotes and TPM certify operations
/// @dev Wraps ITpmAttestation from automata-tpm-attestation library and handles type conversions
///      between our PublicIdentity representation and the library's CertPubkey representation.
///      Designed to be inherited by SessionRegistry following the TeeVerifier pattern.
abstract contract TpmVerifier is TpmBase {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants - TPMA_OBJECT Attribute Masks
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Required attribute bits for TPM certify verification
    /// fixedTPM (0x2) | fixedParent (0x10) | sensitiveDataOrigin (0x20) | userWithAuth (0x40) | sign (0x40000)
    uint32 internal constant TPMA_OBJECT_REQUIRED_SET = 0x40072;

    /// @dev Forbidden attribute bits for TPM certify verification
    /// Allowed bits (may be 0 or 1): {1,4,5,6,10,18} = 0x00040472
    /// Everything else must be zero: ~0x00040472 = 0xFFFBFB8D
    /// stClear (bit 2) and adminWithPolicy (bit 7) are explicitly forbidden.
    uint32 internal constant TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB8D;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TPM report type does not match expected type for this operation
    error UnexpectedTpmReportType(TpmReportType actual, TpmReportType expected);

    /// @notice Verification backend type is not supported for TPM verification
    error UnsupportedTpmBackendType(VerificationBackendType actual);

    /// @notice TPM quote extraData does not match expected nonce
    error TpmQuoteExtraDataMismatch(bytes32 measured, bytes32 expected);

    /// @notice TPM quote PCR measurement check failed inside the TPM library.
    ///         The library only reports a bool, so the count of PCRs in the quote
    ///         is the most we can attach here. Pre-check the quote off-chain to
    ///         identify the offending PCR.
    error TpmQuotePcrCheckFailed(uint256 quotedPcrCount);

    /// @notice TPM quote library verification failed (signature or attest decode)
    error TpmQuoteLibraryFailed();

    /// @notice TPMA_OBJECT attributes contain forbidden bits.
    ///         `forbiddenBitsSet = actual & TPMA_OBJECT_REQUIRED_CLEAR` — the exact
    ///         bits that violated the policy.
    error TpmaObjectForbiddenBitsSet(uint32 actualAttrs, uint32 forbiddenBitsSet);

    /// @notice TPMT_PUBLIC structure is too short
    error TpmtPublicTooShort(uint256 length);

    /// @notice Verifies a TPM Quote report (PCR snapshot with signature)
    /// @param tpmReport The TPM Quote report to verify
    /// @param akPub The Attestation Key public identity (root of trust from AK collateral)
    /// @param expectedExtraData The extraData that must be present in the TPM quote (for nonce binding)
    /// @return result Verification result containing PCR values and AK fingerprint
    function verifyTpmQuote(TpmReport memory tpmReport, PublicIdentity memory akPub, bytes memory expectedExtraData)
        internal
        returns (TpmQuoteVerificationResult memory result)
    {
        // Validate TPM report type
        if (tpmReport.tpmReportType != TpmReportType.TpmQuote) {
            revert UnexpectedTpmReportType(tpmReport.tpmReportType, TpmReportType.TpmQuote);
        }

        // Only Solidity backend supported for now (ZK support planned)
        if (tpmReport.verificationBackendType != VerificationBackendType.Solidity) {
            revert UnsupportedTpmBackendType(tpmReport.verificationBackendType);
        }

        // Decode TPM quote report
        TpmQuoteReport memory quoteReport = abi.decode(tpmReport.data, (TpmQuoteReport));

        // Convert PublicIdentity to CertPubkey for library compatibility
        CertPubkey memory akCertPubkey = LibKey.publicIdentityToCertPubkey(akPub);

        // Verify TPM quote signature with trusted AK (library reverts on failure)
        (bool success, bytes memory extraData) = tpmAttestation.verifyTpmQuoteWithTrustedAkPub(
            quoteReport.tpm2bAttest, quoteReport.tpmSignature, akCertPubkey
        );

        // Library returns false on failure instead of reverting in some paths
        if (!success) revert TpmQuoteLibraryFailed();

        // Validate extraData matches expected nonce
        bytes32 measuredExtra = keccak256(extraData);
        bytes32 expectedExtra = keccak256(expectedExtraData);
        if (measuredExtra != expectedExtra) {
            revert TpmQuoteExtraDataMismatch(measuredExtra, expectedExtra);
        }

        // Check PCR measurements (library emits events, reverts on failure)
        (bool pcrSuccess,) = tpmAttestation.checkPcrMeasurements(quoteReport.tpm2bAttest, quoteReport.pcrValues);

        if (!pcrSuccess) {
            revert TpmQuotePcrCheckFailed(quoteReport.pcrValues.length);
        }

        return TpmQuoteVerificationResult({valid: true, pcrValues: quoteReport.pcrValues});
    }

    /// @notice Verifies a TPM Certify report (key certification with signature)
    /// @param tpmReport The TPM Certify report to verify
    /// @param akPub The Attestation Key public identity (root of trust from AK collateral)
    /// @return result Verification result containing certified key identity and fingerprints
    function verifyTpmCertify(TpmReport memory tpmReport, PublicIdentity memory akPub)
        internal
        view
        returns (TpmCertifyVerificationResult memory result)
    {
        // Validate TPM report type
        if (tpmReport.tpmReportType != TpmReportType.TpmCertify) {
            revert UnexpectedTpmReportType(tpmReport.tpmReportType, TpmReportType.TpmCertify);
        }

        // Only Solidity backend supported for now
        if (tpmReport.verificationBackendType != VerificationBackendType.Solidity) {
            revert UnsupportedTpmBackendType(tpmReport.verificationBackendType);
        }

        // Decode TPM certify report
        TpmCertifyReport memory certifyReport = abi.decode(tpmReport.data, (TpmCertifyReport));

        // Validate CLEAR bits: extract attributes from tpmtPublic[4:8] and check forbidden bits
        _validateClearBits(certifyReport.tpmtPublic);

        // Convert PublicIdentity to CertPubkey
        CertPubkey memory akCertPubkey = LibKey.publicIdentityToCertPubkey(akPub);

        // Verify TPM key certification (library reverts on failure)
        (CertPubkey memory certifiedPubkey,) = tpmAttestation.verifyTpmKeyCertification(
            certifyReport.tpm2bAttest,
            certifyReport.tpmSignature,
            certifyReport.tpmtPublic,
            akCertPubkey,
            TPMA_OBJECT_REQUIRED_SET
        );

        // Convert certified key from CertPubkey to PublicIdentity
        PublicIdentity memory certifiedKey = LibKey.certPubkeyToPublicIdentity(certifiedPubkey);

        // Compute fingerprints
        bytes32 certifiedKeyFingerprint = LibKey.computeKeyFingerprint(certifiedKey);

        return TpmCertifyVerificationResult({
            valid: true, certifiedKey: certifiedKey, certifiedKeyFingerprint: certifiedKeyFingerprint
        });
    }

    /// @dev Validates that forbidden TPMA_OBJECT attribute bits are not set
    /// @param tpmtPublic The TPMT_PUBLIC structure containing attributes at offset 4
    function _validateClearBits(bytes memory tpmtPublic) private pure {
        if (tpmtPublic.length < 8) revert TpmtPublicTooShort(tpmtPublic.length);

        // Extract uint32 attributes from tpmtPublic[4:8] (big-endian)
        uint32 attributes;
        assembly ("memory-safe") {
            // Load the word at offset 4 (skip 0x20 memory header + 4 bytes)
            let ptr := add(tpmtPublic, 0x24)
            // Load 32 bytes and shift right to get the uint32 at the start
            attributes := shr(224, mload(ptr))
        }

        // Check forbidden bits are not set
        uint32 forbidden = attributes & TPMA_OBJECT_REQUIRED_CLEAR;
        if (forbidden != 0) {
            revert TpmaObjectForbiddenBitsSet(attributes, forbidden);
        }
    }
}
