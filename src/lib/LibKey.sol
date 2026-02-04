// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {TPMConstants} from "@automata-network/automata-tpm-attestation/types/TPMConstants.sol";
import {PublicIdentity} from "../types/Common.sol";
import {KEY_DOMAIN, ALGO_ID_RS256, ALGO_ID_ES256} from "../types/Constants.sol";

/// @title LibKey
/// @notice Library for key identity conversions and fingerprinting
/// @dev Provides utilities for converting between PublicIdentity and CertPubkey types,
///      and for computing domain-separated key fingerprints
library LibKey {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Certificate public key algorithm is not supported
    error UnsupportedCertPubkeyAlgorithm(uint16 algo);

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Fingerprinting
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Computes the fingerprint of a PublicIdentity
    /// @dev Fingerprint is domain-separated to prevent cross-context collisions
    /// @param identity The PublicIdentity to fingerprint
    /// @return fingerprint The keccak256 hash of (KEY_DOMAIN, typeId, key)
    function computeKeyFingerprint(PublicIdentity memory identity) internal pure returns (bytes32 fingerprint) {
        return keccak256(abi.encode(KEY_DOMAIN, identity.typeId, identity.key));
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Type Conversions
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Converts CertPubkey (from TPM library) to PublicIdentity (our internal type)
    /// @dev Maps TPM algorithm constants to our standardized algorithm identifiers
    /// @param certPubkey The CertPubkey to convert
    /// @return identity The converted PublicIdentity
    function certPubkeyToPublicIdentity(CertPubkey memory certPubkey)
        internal
        pure
        returns (PublicIdentity memory identity)
    {
        if (certPubkey.algo == TPMConstants.TPM_ALG_RSA) {
            // RSA → ALGO_ID_RS256
            return PublicIdentity({typeId: ALGO_ID_RS256, key: certPubkey.data});
        } else if (certPubkey.algo == TPMConstants.TPM_ALG_ECC && certPubkey.params == TPMConstants.TPM_ECC_NIST_P256) {
            // ECC P-256 → ALGO_ID_ES256
            return PublicIdentity({typeId: ALGO_ID_ES256, key: certPubkey.data});
        } else {
            revert UnsupportedCertPubkeyAlgorithm(certPubkey.algo);
        }
    }

    /// @notice Converts PublicIdentity (our internal type) to CertPubkey (for TPM library)
    /// @dev Maps our standardized algorithm identifiers to TPM algorithm constants
    /// @param identity The PublicIdentity to convert
    /// @return certPubkey The converted CertPubkey
    function publicIdentityToCertPubkey(PublicIdentity memory identity)
        internal
        pure
        returns (CertPubkey memory certPubkey)
    {
        if (identity.typeId == ALGO_ID_RS256) {
            // RSA: TPM_ALG_RSA with params=0
            return CertPubkey({algo: TPMConstants.TPM_ALG_RSA, params: 0, data: identity.key});
        } else if (identity.typeId == ALGO_ID_ES256) {
            // ECC P-256: TPM_ALG_ECC with params=TPM_ECC_NIST_P256
            return
                CertPubkey({algo: TPMConstants.TPM_ALG_ECC, params: TPMConstants.TPM_ECC_NIST_P256, data: identity.key});
        } else {
            revert UnsupportedCertPubkeyAlgorithm(identity.typeId);
        }
    }
}
