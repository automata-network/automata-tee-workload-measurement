// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../interfaces/verifiers/IAkCollateralVerifier.sol";
import {AkPubCollateral, AkPubCollateralType} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibKey} from "../lib/LibKey.sol";

/// @title AkCollateralVerifier
/// @notice Abstract base contract for verifying AK collateral (Azure JWK / GCP cert chain)
/// @dev Wraps ITpmAttestation from automata-tpm-attestation library for cert chain verification
///      and implements custom Azure JWK parsing. Designed to be inherited by SessionRegistry
///      following the TeeVerifier pattern.
abstract contract AkCollateralVerifier is IAkCollateralVerifier {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables - TPM Attestation Contract
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TPM attestation verifier contract from automata-tpm-attestation library
    ITpmAttestation public immutable tpmAttestation;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice AK collateral type is not supported
    error UnsupportedAkCollateralType(AkPubCollateralType collateralType);

    /// @notice Azure JWK parsing failed
    error AzureJwkParsingFailed(string reason);

    /// @notice GCP certificate chain verification failed
    error GcpCertChainVerificationFailed();

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Initializes the AkCollateralVerifier with the TPM attestation contract
    /// @param _tpmAttestation Address of the TPM attestation verifier contract
    constructor(ITpmAttestation _tpmAttestation) {
        tpmAttestation = _tpmAttestation;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Public Interface
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Verifies AK collateral and extracts the AK public key
    /// @param collateral The AK collateral to verify (Azure JWK or GCP cert chain)
    /// @return result Verification result containing AK identity, fingerprint, and binding hash
    function verifyAkCollateral(AkPubCollateral calldata collateral)
        public
        override
        returns (AkCollateralVerificationResult memory result)
    {
        if (collateral.akPubCollateralType == AkPubCollateralType.AzureAkPubJson) {
            return _verifyAzureAkCollateral(collateral.data);
        } else if (collateral.akPubCollateralType == AkPubCollateralType.GcpCertChain) {
            return _verifyGcpAkCollateral(collateral.data);
        } else {
            revert UnsupportedAkCollateralType(collateral.akPubCollateralType);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Azure JWK Parsing
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies Azure AK collateral (JWK JSON format)
    /// @param data The Azure JWK JSON bytes
    /// @return result Verification result with extracted AK public key
    function _verifyAzureAkCollateral(bytes calldata data)
        internal
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
    function _parseAzureJwkAkPub(bytes calldata jsonBytes) internal pure returns (PublicIdentity memory) {
        // Convert bytes to string for parsing
        string memory json = string(jsonBytes);

        // Find "kid":"HCLAkPub" to identify the correct key
        uint256 kidPos = LibString.indexOf(json, '"kid":"HCLAkPub"');
        if (kidPos == type(uint256).max) {
            revert AzureJwkParsingFailed("HCLAkPub not found");
        }

        // Extract "kty" field (must be "RSA")
        uint256 ktyPos = LibString.indexOf(json, '"kty":"');
        if (ktyPos == type(uint256).max) {
            revert AzureJwkParsingFailed("kty field not found");
        }

        // Check if kty is "RSA" (position + 7 chars for "kty":" = start of value)
        string memory ktyValue = LibString.slice(json, ktyPos + 7, ktyPos + 10);
        if (!LibString.eq(ktyValue, "RSA")) {
            revert AzureJwkParsingFailed("kty must be RSA");
        }

        // Extract "n" field (RSA modulus, base64url encoded)
        uint256 nPos = LibString.indexOf(json, '"n":"');
        if (nPos == type(uint256).max) {
            revert AzureJwkParsingFailed("n field not found");
        }

        // Find the closing quote for "n" value
        uint256 nStart = nPos + 5; // Skip '"n":"'
        uint256 nEnd = LibString.indexOf(LibString.slice(json, nStart), '"');
        if (nEnd == type(uint256).max) {
            revert AzureJwkParsingFailed("n field malformed");
        }
        nEnd += nStart;

        string memory nBase64 = LibString.slice(json, nStart, nEnd);

        // Extract "e" field (RSA exponent, base64url encoded)
        uint256 ePos = LibString.indexOf(json, '"e":"');
        if (ePos == type(uint256).max) {
            revert AzureJwkParsingFailed("e field not found");
        }

        uint256 eStart = ePos + 5; // Skip '"e":"'
        uint256 eEnd = LibString.indexOf(LibString.slice(json, eStart), '"');
        if (eEnd == type(uint256).max) {
            revert AzureJwkParsingFailed("e field malformed");
        }
        eEnd += eStart;

        string memory eBase64 = LibString.slice(json, eStart, eEnd);

        // Decode base64url values (Solady Base64 handles base64url transparently)
        bytes memory nBytes = Base64.decode(nBase64);
        bytes memory eBytes = Base64.decode(eBase64);

        // Validate decoded values
        if (nBytes.length == 0) {
            revert AzureJwkParsingFailed("n decode failed");
        }
        if (eBytes.length == 0) {
            revert AzureJwkParsingFailed("e decode failed");
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
    function _verifyGcpAkCollateral(bytes calldata data)
        internal
        returns (AkCollateralVerificationResult memory result)
    {
        // Decode certificate chain
        bytes[] memory certs = abi.decode(data, (bytes[]));

        // Verify certificate chain and extract leaf public key
        // Library caches intermediate certs (non-view), reverts on failure
        CertPubkey memory certPubkey = tpmAttestation.verifyCertChain(certs);

        // Convert to PublicIdentity
        PublicIdentity memory akPub = LibKey.certPubkeyToPublicIdentity(certPubkey);

        // Compute fingerprint
        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);

        // GCP binding: placeholder (user will provide GCP binding spec later)
        // GCP binding is typically via PCR15, handled separately by SessionRegistry
        bytes32 bindingHash = bytes32(0);

        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: akPubFingerprint, bindingHash: bindingHash
        });
    }
}
