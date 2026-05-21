// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {AkPubCollateral} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";

/// @notice Result of AK collateral verification
struct AkCollateralVerificationResult {
    /// @dev True if the AK collateral is valid (signature chain verified)
    bool valid;
    /// @dev Extracted Attestation Key public identity
    PublicIdentity akPub;
    /// @dev Fingerprint of the AK public key (for session binding)
    bytes32 akPubFingerprint;
    /// @dev Expected binding hash from the TEE report (provider-specific).
    ///      Azure: sha256(hclVarData) -- already cross-checked inside AkCollateralVerifier
    ///             against the MAA JWT's tdx_report_data / x-ms-sevsnpvm-reportdata claim, so the
    ///             downstream caller does not need to re-check it against the on-chain teeReport.
    ///      GCP:   bytes32(0). Binding is enforced via PCR15 by SessionRegistry step 7.
    bytes32 bindingHash;
}

interface IAkCollateralVerifier {
    function verifyAkCollateral(AkPubCollateral calldata collateral)
        external
        returns (AkCollateralVerificationResult memory result);
}
