// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {AkPubCollateral, PublicIdentity} from "../../types/Evidence.sol";

/// @notice Result of AK collateral verification
struct AkCollateralVerificationResult {
    /// @dev True if the AK collateral is valid (signature chain verified)
    bool valid;
    /// @dev Extracted Attestation Key public identity
    PublicIdentity akPub;
    /// @dev Fingerprint of the AK public key (for session binding)
    bytes32 akPubFingerprint;
    /// @dev Expected binding hash from the TEE report (provider-specific)
    bytes32 bindingHash;
}

/// @title IAkCollateralVerifier
/// @notice Validates AK public key collateral (Azure JWK / GCP cert chain) and extracts the AK
/// @dev This is the bridge between TEE hardware attestation and the vTPM software attestation
///      The AK collateral proves that the AK public key is bound to the TEE instance
interface IAkCollateralVerifier {
    /// @notice Verifies AK collateral and extracts the AK public key
    /// @param collateral The AK collateral to verify (Azure JWK or GCP cert chain)
    /// @return result Verification result containing AK identity, fingerprint, and binding hash
    function verifyAkCollateral(AkPubCollateral calldata collateral)
        external
        returns (AkCollateralVerificationResult memory result);
}
