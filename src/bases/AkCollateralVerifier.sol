// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {AkPubCollateral, AkPubCollateralType} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";
import {ALGO_ID_RS256} from "../types/Constants.sol";
import {ISignatureVerifier} from "../interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../interfaces/IAkCollateralVerifier.sol";
import {IMaaKeyRegistry, MaaSigningKey} from "../interfaces/registries/IMaaKeyRegistry.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibKey} from "../lib/LibKey.sol";
import {TpmBase} from "./TpmBase.sol";

/// @title AkCollateralVerifier
/// @notice Abstract base contract for verifying AK collateral (Azure MAA JWT / GCP cert chain)
/// @dev Deployed separately from SessionRegistry so Azure JWT parsing and certificate-chain logic
///      do not count against SessionRegistry's EIP-170 runtime size budget.
contract AkCollateralVerifier is IAkCollateralVerifier, TpmBase {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice MAA signing key directory consulted when verifying AzureMaaJwt collateral
    IMaaKeyRegistry public immutable maaKeyRegistry;

    /// @notice Signature verifier used for MAA JWT RS256 signature verification
    ISignatureVerifier public immutable signatureVerifier;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    constructor(IMaaKeyRegistry _maaKeyRegistry, ISignatureVerifier _signatureVerifier, ITpmAttestation _tpmAttestation)
        TpmBase(_tpmAttestation)
    {
        maaKeyRegistry = _maaKeyRegistry;
        signatureVerifier = _signatureVerifier;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice AK collateral type is not supported
    error UnsupportedAkCollateralType();

    /// @notice HCLAkPub JWK field extraction from hclVarData failed
    error AzureJwkParsingFailed();

    /// @notice JWT could not be split into three base64url parts, or a part failed to decode
    error MaaJwtMalformed();

    /// @notice JWT header `alg` is not "RS256"
    error MaaJwtAlgUnsupported();

    /// @notice JWT header is missing a required field
    error MaaJwtHeaderClaimMissing();

    /// @notice JWT claims is missing a required field
    error MaaJwtClaimMissing();

    /// @notice kidHash lookup returned an empty / revoked / expired key
    error MaaKidNotRegistered();

    /// @notice `iss` claim hash does not equal the registered issuerHash
    error MaaJwtIssuerMismatch();

    /// @notice `x-ms-attestation-type` or `x-ms-compliance-status` claim values failed
    error MaaJwtComplianceFailed();

    /// @notice report_data claim is malformed (wrong length, non-hex chars, or non-zero padding)
    error MaaJwtReportDataMalformed();

    /// @notice RS256 signature over header || "." || claims did not verify against the
    ///         registered MAA signing key
    error MaaJwtSignatureInvalid();

    /// @notice sha256(hclVarData) did not equal the JWT report_data claim prefix
    error MaaJwtBindingMismatch();

    /// @notice Verifies AK collateral and extracts the AK public key
    /// @param collateral The AK collateral to verify (Azure MAA JWT bundle or GCP cert chain)
    /// @return result Verification result containing AK identity, fingerprint, and binding hash
    function verifyAkCollateral(AkPubCollateral calldata collateral)
        external
        override
        returns (AkCollateralVerificationResult memory result)
    {
        if (collateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt) {
            return _verifyAzureAkCollateral(collateral.data);
        } else if (collateral.akPubCollateralType == AkPubCollateralType.GcpCertChain) {
            return _verifyGcpAkCollateral(collateral.data);
        } else {
            revert UnsupportedAkCollateralType();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Azure MAA JWT Verification
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies Azure AK collateral (MAA-signed JWT bundle).
    ///      See on-chain-registry-design.md §8.3.1 / §14.9 for the design rationale.
    /// @param data abi.encode((bytes jwt, bytes hclVarData))
    /// @return result Verification result with extracted AK public key from HCLAkPub
    function _verifyAzureAkCollateral(bytes calldata data)
        private
        view
        returns (AkCollateralVerificationResult memory result)
    {
        (bytes memory jwt, bytes memory hclVarData) = abi.decode(data, (bytes, bytes));

        // Split JWT on '.' into header, claims, signature parts (all base64url).
        string memory jwtStr = string(jwt);
        uint256 firstDot = LibString.indexOf(jwtStr, ".");
        if (firstDot == type(uint256).max || firstDot == 0) revert MaaJwtMalformed();
        uint256 secondDot = LibString.indexOf(jwtStr, ".", firstDot + 1);
        if (secondDot == type(uint256).max || secondDot == firstDot + 1) revert MaaJwtMalformed();
        if (secondDot + 1 >= bytes(jwtStr).length) revert MaaJwtMalformed();

        string memory headerB64Url = LibString.slice(jwtStr, 0, firstDot);
        string memory claimsB64Url = LibString.slice(jwtStr, firstDot + 1, secondDot);
        string memory sigB64Url = LibString.slice(jwtStr, secondDot + 1);

        // ── Header: extract kid, validate alg ────────────────────────────────────
        bytes memory headerBytes = Base64.decode(headerB64Url);
        if (headerBytes.length == 0) revert MaaJwtMalformed();
        string memory header = string(headerBytes);

        string memory alg = _jsonExtractStringRequired(header, "alg", true);
        if (!LibString.eq(alg, "RS256")) revert MaaJwtAlgUnsupported();

        string memory kid = _jsonExtractStringRequired(header, "kid", true);

        // ── MAA signing key lookup ────────────────────────────────────────────────
        bytes32 kidHash = keccak256(bytes(kid));
        MaaSigningKey memory key = maaKeyRegistry.getMaaSigningKey(kidHash);
        if (key.pkcs1Pubkey.length == 0 || key.revoked || block.timestamp > key.notAfter) {
            revert MaaKidNotRegistered();
        }

        // ── Signature: verify RS256 over header || "." || claims ─────────────────
        // signingInput = "<headerB64Url>.<claimsB64Url>" — slice up to (not including) the
        // second dot reconstructs exactly that without an extra concat.
        string memory signingInput = LibString.slice(jwtStr, 0, secondDot);
        bytes32 message = sha256(bytes(signingInput));
        bytes memory sig = Base64.decode(sigB64Url);
        if (sig.length == 0) revert MaaJwtMalformed();

        PublicIdentity memory maaIdentity = PublicIdentity({typeId: ALGO_ID_RS256, key: key.pkcs1Pubkey});
        if (!signatureVerifier.verify(maaIdentity, message, sig)) {
            revert MaaJwtSignatureInvalid();
        }

        // ── Claims: iss / attestation-type / compliance-status / report_data ─────
        bytes memory claimsBytes = Base64.decode(claimsB64Url);
        if (claimsBytes.length == 0) revert MaaJwtMalformed();
        string memory claims = string(claimsBytes);

        // iss
        string memory iss = _jsonExtractStringRequired(claims, "iss", false);
        if (keccak256(bytes(iss)) != key.issuerHash) revert MaaJwtIssuerMismatch();

        // x-ms-attestation-type: must be "tdxvm" or "sevsnpvm". The report_data claim name
        // differs accordingly.
        string memory attestationType = _jsonExtractStringRequired(claims, "x-ms-attestation-type", false);
        bool isTdx = LibString.eq(attestationType, "tdxvm");
        bool isSnp = LibString.eq(attestationType, "sevsnpvm");
        if (!isTdx && !isSnp) revert MaaJwtComplianceFailed();

        // x-ms-compliance-status must be "azure-compliant-cvm"
        string memory complianceStatus = _jsonExtractStringRequired(claims, "x-ms-compliance-status", false);
        if (!LibString.eq(complianceStatus, "azure-compliant-cvm")) revert MaaJwtComplianceFailed();

        // report_data: 128-char hex = 64 bytes. First 32 bytes = bindingHash;
        // next 32 bytes must be zero.
        string memory reportDataKey = isTdx ? "tdx_report_data" : "x-ms-sevsnpvm-reportdata";
        string memory reportDataHex = _jsonExtractStringRequired(claims, reportDataKey, false);
        (bytes32 bindingHash, bool paddingZero) = _hexToReportData(reportDataHex);
        if (!paddingZero) revert MaaJwtReportDataMalformed();

        // ── Binding check: sha256(hclVarData) must equal bindingHash ─────────────
        if (sha256(hclVarData) != bindingHash) revert MaaJwtBindingMismatch();

        // ── AK extraction: parse HCLAkPub from hclVarData via §14.3-scoped parser ─
        PublicIdentity memory akPub = _parseAzureJwkAkPub(hclVarData);
        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);

        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: akPubFingerprint, bindingHash: bindingHash
        });
    }

    /// @dev Extracts the string value of a top-level field `"<key>":"..."` from a flat JSON
    ///      document. MAA claim values we read (iss, attestation-type, compliance-status,
    ///      report_data hex strings, header kid/alg) are simple ASCII without escapes, and
    ///      none of them sit inside a nested object — so this naive search is sufficient.
    /// @param json Flat JSON string
    /// @param fieldKey The key to search for (without quotes)
    /// @param headerNotClaims Selects which error to revert with on a missing field
    function _jsonExtractStringRequired(string memory json, string memory fieldKey, bool headerNotClaims)
        private
        pure
        returns (string memory)
    {
        // Search for the literal pattern: "fieldKey":"
        string memory needle = string(abi.encodePacked('"', fieldKey, '":"'));
        uint256 pos = LibString.indexOf(json, needle);
        if (pos == type(uint256).max) {
            if (headerNotClaims) revert MaaJwtHeaderClaimMissing();
            revert MaaJwtClaimMissing();
        }
        uint256 valStart = pos + bytes(needle).length;
        // Find the closing quote of the value (no escape handling — claims we read are
        // simple ASCII strings without embedded backslashes or quotes).
        uint256 valEnd = LibString.indexOf(json, '"', valStart);
        if (valEnd == type(uint256).max) {
            if (headerNotClaims) revert MaaJwtHeaderClaimMissing();
            revert MaaJwtClaimMissing();
        }
        return LibString.slice(json, valStart, valEnd);
    }

    /// @dev Hex-decodes a 128-character ASCII hex string into a (bindingHash, paddingZero) pair.
    ///      The first 32 bytes (64 chars) become bindingHash; the next 32 bytes (64 chars)
    ///      must decode to bytes32(0). Reverts MaaJwtReportDataMalformed on wrong length or
    ///      non-hex characters; returns paddingZero=false to signal a non-zero padding (caller
    ///      reverts with the same error code).
    function _hexToReportData(string memory hexStr) private pure returns (bytes32 bindingHash, bool paddingZero) {
        bytes memory s = bytes(hexStr);
        if (s.length != 128) revert MaaJwtReportDataMalformed();

        uint256 acc;
        // First 64 chars → bindingHash
        for (uint256 i = 0; i < 64; i++) {
            acc = (acc << 4) | _hexDigit(uint8(s[i]));
        }
        bindingHash = bytes32(acc);

        // Next 64 chars → must decode to zero
        uint256 padAcc;
        for (uint256 i = 64; i < 128; i++) {
            padAcc = (padAcc << 4) | _hexDigit(uint8(s[i]));
        }
        paddingZero = (padAcc == 0);
    }

    /// @dev Returns the numeric value (0-15) of a single ASCII hex digit. Reverts on non-hex.
    function _hexDigit(uint8 c) private pure returns (uint256) {
        unchecked {
            if (c >= 0x30 && c <= 0x39) return c - 0x30; // '0'-'9'
            if (c >= 0x61 && c <= 0x66) return c - 0x57; // 'a'-'f' → 10..15
            if (c >= 0x41 && c <= 0x46) return c - 0x37; // 'A'-'F' → 10..15
            revert MaaJwtReportDataMalformed();
        }
    }

    /// @dev Parses Azure JWK JSON (within hclVarData) to extract the HCLAkPub RSA public key.
    ///      Scope guard per §14.3: the kid/n/e/kty lookup is constrained to the JWK object
    ///      containing "kid":"HCLAkPub", so the result is independent of keys[] ordering.
    /// @param jsonBytes The hclVarData JSON bytes (from vTPM NV 0x01400001)
    /// @return PublicIdentity wrapping the extracted RSA public key
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
    function _verifyGcpAkCollateral(bytes calldata data)
        private
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

        // GCP binding is typically via PCR15, handled separately by SessionRegistry
        bytes32 bindingHash = bytes32(0);

        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: akPubFingerprint, bindingHash: bindingHash
        });
    }
}
