// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TpmReport, PcrValue, PublicIdentity} from "../../types/Evidence.sol";

/// @notice Result of TPM Quote verification
struct TpmQuoteVerificationResult {
    /// @dev True if the TPM quote signature is valid and structure is well-formed
    bool valid;
    /// @dev PCR values extracted from the quote (with event logs for DYNAMIC verification)
    PcrValue[] pcrValues;
    /// @dev Fingerprint of the Attestation Key that signed the quote
    bytes32 akPubFingerprint;
}

/// @notice Result of TPM Certify verification
struct TpmCertifyVerificationResult {
    /// @dev True if the TPM certify signature is valid and structure is well-formed
    bool valid;
    /// @dev Public identity of the certified key (extracted from TPMT_PUBLIC)
    PublicIdentity certifiedKey;
    /// @dev Fingerprint of the certified key (for session binding)
    bytes32 certifiedKeyFingerprint;
    /// @dev Fingerprint of the Attestation Key that signed the certify report
    bytes32 akPubFingerprint;
}

/// @title ITpmVerifier
/// @notice Verifies TPM quotes (PCR measurements) and TPM certify operations (key co-residency proof)
/// @dev Bridge between TEE hardware attestation and vTPM software attestation
interface ITpmVerifier {
    /// @notice Verifies a TPM Quote report (PCR snapshot with signature)
    /// @param tpmReport The TPM Quote report to verify
    /// @param akPub The Attestation Key public identity (root of trust from AK collateral)
    /// @param expectedExtraData The extraData that must be present in the TPM quote (for nonce binding)
    /// @return result Verification result containing PCR values and AK fingerprint
    function verifyTpmQuote(TpmReport calldata tpmReport, PublicIdentity calldata akPub, bytes32 expectedExtraData)
        external
        returns (TpmQuoteVerificationResult memory result);

    /// @notice Verifies a TPM Certify report (key certification with signature)
    /// @param tpmReport The TPM Certify report to verify
    /// @param akPub The Attestation Key public identity (root of trust from AK collateral)
    /// @return result Verification result containing certified key identity and fingerprints
    function verifyTpmCertify(TpmReport calldata tpmReport, PublicIdentity calldata akPub)
        external
        view
        returns (TpmCertifyVerificationResult memory result);
}
