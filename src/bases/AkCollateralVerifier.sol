// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {AkPubCollateral, AkPubCollateralType} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibKey} from "../lib/LibKey.sol";
import {TpmBase} from "./TpmBase.sol";

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

/// @title AkCollateralVerifier
/// @notice Abstract base contract for verifying AK collateral (Azure JWK / GCP cert chain)
/// @dev Wraps ITpmAttestation from automata-tpm-attestation library for cert chain verification
///      and implements custom Azure JWK parsing. Designed to be inherited by SessionRegistry
///      following the TeeVerifier pattern.
abstract contract AkCollateralVerifier is TpmBase {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice AK collateral type is not supported
    error UnsupportedAkCollateralType();

    /// @notice Azure JWK parsing failed
    error AzureJwkParsingFailed();

    /// @notice Verifies AK collateral and extracts the AK public key
    /// @param collateral The AK collateral to verify (Azure JWK or GCP cert chain)
    /// @return result Verification result containing AK identity, fingerprint, and binding hash
    function verifyAkCollateral(AkPubCollateral memory collateral)
        internal
        returns (AkCollateralVerificationResult memory result)
    {
        if (collateral.akPubCollateralType == AkPubCollateralType.AzureAkPubJson) {
            return _verifyAzureAkCollateral(collateral.data);
        } else if (collateral.akPubCollateralType == AkPubCollateralType.GcpCertChain) {
            return _verifyGcpAkCollateral(collateral.data);
        } else {
            revert UnsupportedAkCollateralType();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Azure JWK Parsing
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies Azure AK collateral (JWK JSON format)
    /// @param data The Azure JWK JSON bytes
    /// @return result Verification result with extracted AK public key
    function _verifyAzureAkCollateral(bytes memory data)
        private
        pure
        returns (AkCollateralVerificationResult memory result)
    {
        // Parse Azure JWK to extract RSA public key
        PublicIdentity memory akPub = _parseAzureJwkAkPub(data);

        // Compute fingerprint
        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);

        // Azure binding: sha256 hash of the JWK JSON (embedded in TEE REPORT_DATA)
        bytes32 bindingHash = sha256(data);

        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: akPubFingerprint, bindingHash: bindingHash
        });
    }

    /// @dev Parses Azure JWK JSON to extract RSA public key
    /// @param jsonBytes The Azure JWK JSON bytes
    /// @return certPubkey The extracted RSA public key as CertPubkey
    function _parseAzureJwkAkPub(bytes memory jsonBytes) private pure returns (PublicIdentity memory) {
        // Convert bytes to string for parsing
        string memory fullJson = string(jsonBytes);
        bool ok = true;

        // Locate the JWK object containing "kid":"HCLAkPub" and scope all field
        // lookups to that object. JWKs do not nest objects in their parameter
        // values, so the enclosing object runs from the nearest preceding `{`
        // to the next `}` after the kid marker.
        uint256 kidPos = LibString.indexOf(fullJson, '"kid":"HCLAkPub"');
        if (kidPos == type(uint256).max) ok = false;

        string memory json;
        if (ok) {
            uint256 objStart = LibString.lastIndexOf(fullJson, "{", kidPos);
            uint256 objEnd = LibString.indexOf(fullJson, "}", kidPos);
            if (objStart == type(uint256).max || objEnd == type(uint256).max) {
                ok = false;
            } else {
                json = LibString.slice(fullJson, objStart, objEnd + 1);
            }
        }

        // Extract "kty" field (must be "RSA") within the scoped JWK object
        uint256 ktyPos;
        if (ok) {
            ktyPos = LibString.indexOf(json, '"kty":"');
            if (ktyPos == type(uint256).max) ok = false;
        }

        // Check if kty is "RSA" (position + 7 chars for "kty":" = start of value)
        if (ok) {
            string memory ktyValue = LibString.slice(json, ktyPos + 7, ktyPos + 10);
            if (!LibString.eq(ktyValue, "RSA")) ok = false;
        }

        // Extract "n" field (RSA modulus, base64url encoded)
        uint256 nPos;
        if (ok) {
            nPos = LibString.indexOf(json, '"n":"');
            if (nPos == type(uint256).max) ok = false;
        }

        // Find the closing quote for "n" value
        uint256 nStart;
        uint256 nEnd;
        string memory nBase64;
        if (ok) {
            nStart = nPos + 5; // Skip '"n":"'
            nEnd = LibString.indexOf(LibString.slice(json, nStart), '"');
            if (nEnd == type(uint256).max) {
                ok = false;
            } else {
                nEnd += nStart;
            }
        }
        if (ok) {
            nBase64 = LibString.slice(json, nStart, nEnd);
        }

        // Extract "e" field (RSA exponent, base64url encoded)
        uint256 ePos;
        if (ok) {
            ePos = LibString.indexOf(json, '"e":"');
            if (ePos == type(uint256).max) ok = false;
        }

        uint256 eStart;
        uint256 eEnd;
        string memory eBase64;
        if (ok) {
            eStart = ePos + 5; // Skip '"e":"'
            eEnd = LibString.indexOf(LibString.slice(json, eStart), '"');
            if (eEnd == type(uint256).max) {
                ok = false;
            } else {
                eEnd += eStart;
            }
        }
        if (ok) {
            eBase64 = LibString.slice(json, eStart, eEnd);
        }

        // Decode base64url values (Solady Base64 handles base64url transparently)
        bytes memory nBytes = ok ? Base64.decode(nBase64) : bytes("");
        bytes memory eBytes = ok ? Base64.decode(eBase64) : bytes("");

        // Validate decoded values
        if (nBytes.length == 0 || eBytes.length == 0) ok = false;

        if (!ok) {
            revert AzureJwkParsingFailed();
        }

        // Build RSA public key using LibX509
        CertPubkey memory akCertPubKey = LibX509.newRsaPubkey(nBytes, eBytes);
        return LibKey.certPubkeyToPublicIdentity(akCertPubKey);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - GCP Certificate Chain Verification
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies GCP AK collateral (X.509 certificate chain)
    /// @param data The GCP certificate chain (abi-encoded bytes[] array)
    /// @return result Verification result with extracted AK public key
    function _verifyGcpAkCollateral(bytes memory data) private returns (AkCollateralVerificationResult memory result) {
        // Decode certificate chain
        bytes[] memory certs = abi.decode(data, (bytes[]));

        // Verify certificate chain and extract leaf public key
        // Library caches intermediate certs (non-view), reverts on failure
        CertPubkey memory certPubkey = tpmAttestation.verifyCertChain(certs);

        // Convert to PublicIdentity
        PublicIdentity memory akPub = LibKey.certPubkeyToPublicIdentity(certPubkey);

        // Compute fingerprint
        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);

        // GCP binding is typically via PCR15, handled separately by SessionRegistry
        bytes32 bindingHash = bytes32(0);

        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: akPubFingerprint, bindingHash: bindingHash
        });
    }
}
