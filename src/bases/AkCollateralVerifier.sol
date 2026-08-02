// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {AkPubCollateral, AkPubCollateralType, TEEType, VerificationBackendType} from "../types/Evidence.sol";
import {PublicIdentity} from "../types/Common.sol";
import {AwsNitroTpmJournalV1, ProgramBoundZkProof, ZkProofType} from "../types/Zk.sol";
import {ALGO_ID_ES256, ALGO_ID_RS256} from "../types/Constants.sol";
import {ISignatureVerifier} from "../interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../interfaces/IAkCollateralVerifier.sol";
import {IMaaKeyRegistry, MaaSigningKey} from "../interfaces/registries/IMaaKeyRegistry.sol";
import {IZkVerifierRegistry} from "../interfaces/registries/IZkVerifierRegistry.sol";
import {IAwsNitroTpmZkVerifierAdapter} from "../interfaces/zk/IZkVerifierAdapters.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibKey} from "../lib/LibKey.sol";
import {TpmBase} from "./TpmBase.sol";

/// @title AkCollateralVerifier
/// @notice Separately deployed verifier for Azure MAA JWT, GCP certificate-chain, and AWS NitroTPM proof collateral
/// @dev Deployed separately from SessionRegistry so Azure JWT parsing and certificate-chain logic
///      do not count against SessionRegistry's EIP-170 runtime size budget.
contract AkCollateralVerifier is IAkCollateralVerifier, TpmBase {
    uint256 private constant P256_FIELD_MODULUS = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice MAA signing key directory consulted when verifying AzureMaaJwt collateral
    IMaaKeyRegistry public immutable maaKeyRegistry;

    /// @notice Signature verifier used for MAA JWT RS256 signature verification
    ISignatureVerifier public immutable signatureVerifier;

    IZkVerifierRegistry public immutable zkVerifierRegistry;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    constructor(
        IMaaKeyRegistry _maaKeyRegistry,
        ISignatureVerifier _signatureVerifier,
        ITpmAttestation _tpmAttestation,
        IZkVerifierRegistry _zkVerifierRegistry
    ) TpmBase(_tpmAttestation) {
        maaKeyRegistry = _maaKeyRegistry;
        signatureVerifier = _signatureVerifier;
        zkVerifierRegistry = _zkVerifierRegistry;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    error AkCollateralBackendNotConfigured(
        AkPubCollateralType akPubCollateralType, VerificationBackendType verificationBackendType
    );
    error InvalidAttestationKeyAlgorithm(AkPubCollateralType collateralType, uint8 actualTypeId);
    error InvalidAttestationKeyEncoding(AkPubCollateralType collateralType);

    /// @notice HCLAkPub JWK field extraction from hclVarData failed
    error AzureJwkParsingFailed();

    /// @notice JWT could not be split into three base64url parts (header.claims.sig).
    ///         segmentCount is the number of '.'-separated non-empty parts observed.
    error MaaJwtStructureInvalid(uint8 segmentCount);

    /// @notice Base64url decode of a JWT segment produced zero bytes.
    ///         segment: 0=header, 1=claims, 2=signature.
    error MaaJwtBase64DecodeFailed(uint8 segment);

    /// @notice JWT header `alg` is not "RS256"
    error MaaJwtAlgUnsupported(bytes32 algHash);

    /// @notice JWT header is missing a required field. fieldNameHash = keccak256(name).
    ///         See FIELD_HASH_* constants for the canonical mapping.
    error MaaJwtHeaderClaimMissing(bytes32 fieldNameHash);

    /// @notice JWT claims object is missing a required field. fieldNameHash = keccak256(name).
    error MaaJwtClaimMissing(bytes32 fieldNameHash);

    /// @notice A required numeric JWT claim is not a canonical unsigned 64-bit integer.
    error MaaJwtNumericClaimMalformed(bytes32 fieldNameHash);

    /// @notice The JWT validity interval is empty or its issue time is not before expiry.
    error MaaJwtValidityWindowInvalid(uint64 issuedAt, uint64 notBefore, uint64 expiresAt);

    /// @notice The JWT cannot be accepted before its `nbf` time.
    error MaaJwtNotYetValid(uint64 notBefore, uint256 verificationTime);

    /// @notice The JWT cannot be accepted at or after its `exp` time.
    error MaaJwtExpired(uint64 expiresAt, uint256 verificationTime);

    /// @notice The JWT claims an `iat` later than the verification time.
    error MaaJwtIssuedInFuture(uint64 issuedAt, uint256 verificationTime);

    /// @notice kidHash lookup returned an empty / revoked / expired key
    error MaaKidNotRegistered(bytes32 kidHash);

    /// @notice `iss` claim hash does not equal the registered issuerHash
    error MaaJwtIssuerMismatch(bytes32 actual, bytes32 expected);

    /// @notice `x-ms-attestation-type` claim is neither "tdxvm" nor "sevsnpvm"
    error MaaJwtAttestationTypeUnsupported(bytes32 attestationTypeHash);

    /// @notice `x-ms-compliance-status` claim is not "azure-compliant-cvm"
    error MaaJwtComplianceFailed(bytes32 complianceStatusHash);

    /// @notice report_data claim is malformed. badCharOffset is the index of the
    ///         first non-hex character, or type(uint256).max if length itself is wrong.
    error MaaJwtReportDataMalformed(uint256 length, uint256 badCharOffset);

    /// @notice RS256 signature over header || "." || claims did not verify against the
    ///         registered MAA signing key
    error MaaJwtSignatureInvalid(bytes32 kidHash);

    /// @notice sha256(hclVarData) did not equal the JWT report_data claim prefix
    error MaaJwtBindingMismatch(bytes32 measured, bytes32 expected);

    // ─── Field-name hashes (canonical mapping for the *Missing errors) ───
    // Solidity 0.8.x folds keccak256 of a literal at compile time, so off-chain decoders
    // can map the hash in the error back to the field name.
    bytes32 internal constant FIELD_HASH_ALG = keccak256("alg");
    bytes32 internal constant FIELD_HASH_KID = keccak256("kid");
    bytes32 internal constant FIELD_HASH_ISS = keccak256("iss");
    bytes32 internal constant FIELD_HASH_EXP = keccak256("exp");
    bytes32 internal constant FIELD_HASH_NBF = keccak256("nbf");
    bytes32 internal constant FIELD_HASH_IAT = keccak256("iat");
    bytes32 internal constant FIELD_HASH_ATTESTATION_TYPE = keccak256("x-ms-attestation-type");
    bytes32 internal constant FIELD_HASH_COMPLIANCE_STATUS = keccak256("x-ms-compliance-status");
    bytes32 internal constant FIELD_HASH_TDX_REPORT_DATA = keccak256("tdx_report_data");
    bytes32 internal constant FIELD_HASH_SNP_REPORT_DATA = keccak256("x-ms-sevsnpvm-reportdata");

    /// @notice Verifies AK collateral and extracts the AK public key
    /// @param collateral The AK collateral to verify (Azure MAA JWT bundle or GCP cert chain)
    /// @return result Verification result containing AK identity, fingerprint, and binding hash
    function verifyAkCollateral(AkPubCollateral calldata collateral)
        external
        override
        returns (AkCollateralVerificationResult memory result)
    {
        if (
            collateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt
                && collateral.verificationBackendType == VerificationBackendType.Solidity
        ) {
            return _verifyAzureAkCollateral(collateral.data);
        } else if (
            collateral.akPubCollateralType == AkPubCollateralType.GcpCertChain
                && collateral.verificationBackendType == VerificationBackendType.Solidity
        ) {
            return _verifyGcpAkCollateral(collateral.data);
        } else if (
            collateral.akPubCollateralType == AkPubCollateralType.AwsNitroTpmProof
                && collateral.verificationBackendType == VerificationBackendType.ZkSuccinct
        ) {
            return _verifyAwsNitroTpmCollateral(collateral.data, collateral.verificationBackendType);
        }
        revert AkCollateralBackendNotConfigured(collateral.akPubCollateralType, collateral.verificationBackendType);
    }

    function validateAkPub(AkPubCollateralType collateralType, PublicIdentity calldata akPub)
        external
        pure
        override
        returns (bytes32 fingerprint)
    {
        if (collateralType == AkPubCollateralType.AzureMaaJwt) {
            if (akPub.typeId != ALGO_ID_RS256) {
                revert InvalidAttestationKeyAlgorithm(collateralType, akPub.typeId);
            }
            if (akPub.key.length == 0) revert InvalidAttestationKeyEncoding(collateralType);
        } else {
            if (akPub.typeId != ALGO_ID_ES256) {
                revert InvalidAttestationKeyAlgorithm(collateralType, akPub.typeId);
            }
            if (!_isValidP256Point(akPub.key)) revert InvalidAttestationKeyEncoding(collateralType);
        }
        return LibKey.computeKeyFingerprint(akPub);
    }

    function _isValidP256Point(bytes calldata key) private pure returns (bool) {
        if (key.length != 65 || key[0] != 0x04) return false;
        uint256 x = uint256(bytes32(key[1:33]));
        uint256 y = uint256(bytes32(key[33:65]));
        if (x >= P256_FIELD_MODULUS || y >= P256_FIELD_MODULUS) return false;
        uint256 left = mulmod(y, y, P256_FIELD_MODULUS);
        uint256 xSquared = mulmod(x, x, P256_FIELD_MODULUS);
        uint256 xCubed = mulmod(xSquared, x, P256_FIELD_MODULUS);
        uint256 threeX = mulmod(3, x, P256_FIELD_MODULUS);
        uint256 right = addmod(xCubed, P256_FIELD_MODULUS - threeX, P256_FIELD_MODULUS);
        right = addmod(right, P256_B, P256_FIELD_MODULUS);
        return left == right;
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
        // segmentCount counts the non-empty segments observed so far so the error
        // can distinguish "no dots", "one dot", "trailing dot empty" etc.
        string memory jwtStr = string(jwt);
        uint256 firstDot = LibString.indexOf(jwtStr, ".");
        if (firstDot == type(uint256).max) revert MaaJwtStructureInvalid(1);
        if (firstDot == 0) revert MaaJwtStructureInvalid(0);
        uint256 secondDot = LibString.indexOf(jwtStr, ".", firstDot + 1);
        if (secondDot == type(uint256).max) revert MaaJwtStructureInvalid(2);
        if (secondDot == firstDot + 1) revert MaaJwtStructureInvalid(1);
        if (secondDot + 1 >= bytes(jwtStr).length) revert MaaJwtStructureInvalid(2);

        string memory headerB64Url = LibString.slice(jwtStr, 0, firstDot);
        string memory claimsB64Url = LibString.slice(jwtStr, firstDot + 1, secondDot);
        string memory sigB64Url = LibString.slice(jwtStr, secondDot + 1);

        // ── Header: extract kid, validate alg ────────────────────────────────────
        bytes memory headerBytes = Base64.decode(headerB64Url);
        if (headerBytes.length == 0) revert MaaJwtBase64DecodeFailed(0);
        string memory header = string(headerBytes);

        string memory alg = _jsonExtractStringRequired(header, "alg", FIELD_HASH_ALG, true);
        if (!LibString.eq(alg, "RS256")) revert MaaJwtAlgUnsupported(keccak256(bytes(alg)));

        string memory kid = _jsonExtractStringRequired(header, "kid", FIELD_HASH_KID, true);

        // ── MAA signing key lookup ────────────────────────────────────────────────
        bytes32 kidHash = keccak256(bytes(kid));
        MaaSigningKey memory key = maaKeyRegistry.getMaaSigningKey(kidHash);
        if (key.pkcs1Pubkey.length == 0 || key.revoked || block.timestamp > key.notAfter) {
            revert MaaKidNotRegistered(kidHash);
        }

        // ── Signature: verify RS256 over header || "." || claims ─────────────────
        // signingInput = "<headerB64Url>.<claimsB64Url>" — slice up to (not including) the
        // second dot reconstructs exactly that without an extra concat.
        string memory signingInput = LibString.slice(jwtStr, 0, secondDot);
        bytes32 message = sha256(bytes(signingInput));
        bytes memory sig = Base64.decode(sigB64Url);
        if (sig.length == 0) revert MaaJwtBase64DecodeFailed(2);

        PublicIdentity memory maaIdentity = PublicIdentity({typeId: ALGO_ID_RS256, key: key.pkcs1Pubkey});
        if (!signatureVerifier.verify(maaIdentity, message, sig)) {
            revert MaaJwtSignatureInvalid(kidHash);
        }

        // ── Claims: iss / attestation-type / compliance-status / report_data ─────
        bytes memory claimsBytes = Base64.decode(claimsB64Url);
        if (claimsBytes.length == 0) revert MaaJwtBase64DecodeFailed(1);
        string memory claims = string(claimsBytes);

        // iss
        string memory iss = _jsonExtractStringRequired(claims, "iss", FIELD_HASH_ISS, false);
        bytes32 issHash = keccak256(bytes(iss));
        if (issHash != key.issuerHash) revert MaaJwtIssuerMismatch(issHash, key.issuerHash);

        // JWT NumericDate claims use the same block timestamp as the MAA signing-key
        // validity check above. `exp` is exclusive; `nbf` is inclusive.
        uint64 expiresAt = _jsonExtractUint64Required(claims, "exp", FIELD_HASH_EXP);
        uint64 notBefore = _jsonExtractUint64Required(claims, "nbf", FIELD_HASH_NBF);
        uint64 issuedAt = _jsonExtractUint64Required(claims, "iat", FIELD_HASH_IAT);
        if (notBefore >= expiresAt || issuedAt >= expiresAt) {
            revert MaaJwtValidityWindowInvalid(issuedAt, notBefore, expiresAt);
        }
        if (block.timestamp < notBefore) revert MaaJwtNotYetValid(notBefore, block.timestamp);
        if (block.timestamp >= expiresAt) revert MaaJwtExpired(expiresAt, block.timestamp);
        if (block.timestamp < issuedAt) revert MaaJwtIssuedInFuture(issuedAt, block.timestamp);

        // x-ms-attestation-type: must be "tdxvm" or "sevsnpvm". The report_data claim name
        // differs accordingly.
        string memory attestationType =
            _jsonExtractStringRequired(claims, "x-ms-attestation-type", FIELD_HASH_ATTESTATION_TYPE, false);
        bool isTdx = LibString.eq(attestationType, "tdxvm");
        bool isSnp = LibString.eq(attestationType, "sevsnpvm");
        if (!isTdx && !isSnp) revert MaaJwtAttestationTypeUnsupported(keccak256(bytes(attestationType)));

        // x-ms-compliance-status must be "azure-compliant-cvm"
        string memory complianceStatus =
            _jsonExtractStringRequired(claims, "x-ms-compliance-status", FIELD_HASH_COMPLIANCE_STATUS, false);
        if (!LibString.eq(complianceStatus, "azure-compliant-cvm")) {
            revert MaaJwtComplianceFailed(keccak256(bytes(complianceStatus)));
        }

        // report_data: 128-char hex = 64 bytes. First 32 bytes = bindingHash;
        // next 32 bytes must be zero.
        string memory reportDataKey;
        bytes32 reportDataKeyHash;
        if (isTdx) {
            reportDataKey = "tdx_report_data";
            reportDataKeyHash = FIELD_HASH_TDX_REPORT_DATA;
        } else {
            reportDataKey = "x-ms-sevsnpvm-reportdata";
            reportDataKeyHash = FIELD_HASH_SNP_REPORT_DATA;
        }
        string memory reportDataHex = _jsonExtractStringRequired(claims, reportDataKey, reportDataKeyHash, false);
        (bytes32 bindingHash, bool paddingZero) = _hexToReportData(reportDataHex);
        if (!paddingZero) {
            // length already validated; non-zero padding is the only path to here
            revert MaaJwtReportDataMalformed(bytes(reportDataHex).length, type(uint256).max);
        }

        // ── Binding check: sha256(hclVarData) must equal bindingHash ─────────────
        bytes32 measuredBinding = sha256(hclVarData);
        if (measuredBinding != bindingHash) revert MaaJwtBindingMismatch(measuredBinding, bindingHash);

        // ── AK extraction: parse HCLAkPub from hclVarData via §14.3-scoped parser ─
        PublicIdentity memory akPub = _parseAzureJwkAkPub(hclVarData);
        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);

        return AkCollateralVerificationResult({
            akPubFingerprint: akPubFingerprint,
            teeType: isTdx ? TEEType.IntelTDX : TEEType.AmdSevSnp,
            bindingHash: bindingHash,
            amdSevSnpReportHash: bytes32(0),
            awsNitroRootCertHash: bytes32(0),
            qualifyingData: bytes32(0),
            documentTimestampSeconds: 0,
            sha384PcrSetCommitment: bytes32(0)
        });
    }

    /// @dev Extracts the string value of a top-level JSON field. MAA claim values
    ///      read here are simple ASCII without escapes.
    /// @param json JSON object
    /// @param fieldKey The key to search for (without quotes)
    /// @param fieldKeyHash keccak256(fieldKey) — reported in the missing-field error so the
    ///        caller can decode which field went missing (see FIELD_HASH_* constants).
    /// @param headerNotClaims Selects which error to revert with on a missing field
    function _jsonExtractStringRequired(
        string memory json,
        string memory fieldKey,
        bytes32 fieldKeyHash,
        bool headerNotClaims
    ) private pure returns (string memory) {
        bytes memory raw = bytes(json);
        uint256 valStart = _jsonFindTopLevelFieldValue(raw, bytes(fieldKey));
        if (valStart == type(uint256).max || valStart >= raw.length || raw[valStart] != 0x22) {
            if (headerNotClaims) revert MaaJwtHeaderClaimMissing(fieldKeyHash);
            revert MaaJwtClaimMissing(fieldKeyHash);
        }
        // Find the closing quote of the value (no escape handling — claims we read are
        // simple ASCII strings without embedded backslashes or quotes).
        uint256 valEnd = valStart + 1;
        while (valEnd < raw.length && raw[valEnd] != 0x22) {
            if (raw[valEnd] == 0x5c) {
                if (headerNotClaims) revert MaaJwtHeaderClaimMissing(fieldKeyHash);
                revert MaaJwtClaimMissing(fieldKeyHash);
            }
            unchecked {
                ++valEnd;
            }
        }
        if (valEnd >= raw.length) {
            if (headerNotClaims) revert MaaJwtHeaderClaimMissing(fieldKeyHash);
            revert MaaJwtClaimMissing(fieldKeyHash);
        }
        return LibString.slice(json, valStart + 1, valEnd);
    }

    /// @dev Extracts a required top-level JWT NumericDate claim. The value must
    ///      use canonical JSON unsigned-integer syntax and fit in uint64.
    function _jsonExtractUint64Required(string memory json, string memory fieldKey, bytes32 fieldKeyHash)
        private
        pure
        returns (uint64 value)
    {
        bytes memory raw = bytes(json);
        uint256 cursor = _jsonFindTopLevelFieldValue(raw, bytes(fieldKey));
        if (cursor == type(uint256).max) revert MaaJwtClaimMissing(fieldKeyHash);
        if (cursor >= raw.length || uint8(raw[cursor]) < 0x30 || uint8(raw[cursor]) > 0x39) {
            revert MaaJwtNumericClaimMalformed(fieldKeyHash);
        }

        uint256 firstDigit = cursor;
        uint256 parsed;
        while (cursor < raw.length) {
            uint8 c = uint8(raw[cursor]);
            if (c < 0x30 || c > 0x39) break;
            uint256 digit = c - 0x30;
            if (parsed > (type(uint64).max - digit) / 10) {
                revert MaaJwtNumericClaimMalformed(fieldKeyHash);
            }
            parsed = parsed * 10 + digit;
            unchecked {
                ++cursor;
            }
        }
        if (cursor - firstDigit > 1 && raw[firstDigit] == 0x30) {
            revert MaaJwtNumericClaimMalformed(fieldKeyHash);
        }
        while (cursor < raw.length && _isJsonWhitespace(uint8(raw[cursor]))) {
            unchecked {
                ++cursor;
            }
        }
        if (cursor >= raw.length || (raw[cursor] != 0x2c && raw[cursor] != 0x7d)) {
            revert MaaJwtNumericClaimMalformed(fieldKeyHash);
        }
        // Safe because the accumulation loop rejects every value above uint64.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(parsed);
    }

    /// @dev Returns the first byte of a top-level field value. Nested objects,
    ///      nested arrays, string contents, and escaped string bytes cannot
    ///      supply a top-level claim.
    function _jsonFindTopLevelFieldValue(bytes memory json, bytes memory fieldKey) private pure returns (uint256) {
        uint256 depth;
        uint256 cursor;
        while (cursor < json.length) {
            uint8 c = uint8(json[cursor]);
            if (c == 0x22) {
                uint256 keyStart = cursor + 1;
                cursor = keyStart;
                bool escaped;
                while (cursor < json.length) {
                    c = uint8(json[cursor]);
                    if (c == 0x5c) {
                        escaped = true;
                        cursor += 2;
                        continue;
                    }
                    if (c == 0x22) break;
                    unchecked {
                        ++cursor;
                    }
                }
                if (cursor >= json.length) return type(uint256).max;
                uint256 keyEnd = cursor;
                unchecked {
                    ++cursor;
                }
                while (cursor < json.length && _isJsonWhitespace(uint8(json[cursor]))) {
                    unchecked {
                        ++cursor;
                    }
                }
                if (
                    !escaped && depth == 1 && cursor < json.length && json[cursor] == 0x3a
                        && _jsonRangeEquals(json, keyStart, keyEnd, fieldKey)
                ) {
                    unchecked {
                        ++cursor;
                    }
                    while (cursor < json.length && _isJsonWhitespace(uint8(json[cursor]))) {
                        unchecked {
                            ++cursor;
                        }
                    }
                    return cursor;
                }
                continue;
            }
            if (c == 0x7b || c == 0x5b) {
                unchecked {
                    ++depth;
                }
            } else if (c == 0x7d || c == 0x5d) {
                if (depth == 0) return type(uint256).max;
                unchecked {
                    --depth;
                }
            }
            unchecked {
                ++cursor;
            }
        }
        return type(uint256).max;
    }

    function _jsonRangeEquals(bytes memory json, uint256 start, uint256 end, bytes memory expected)
        private
        pure
        returns (bool)
    {
        if (end - start != expected.length) return false;
        for (uint256 i = 0; i < expected.length; i++) {
            if (json[start + i] != expected[i]) return false;
        }
        return true;
    }

    function _isJsonWhitespace(uint8 c) private pure returns (bool) {
        return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d;
    }

    /// @dev Hex-decodes a 128-character ASCII hex string into a (bindingHash, paddingZero) pair.
    ///      The first 32 bytes (64 chars) become bindingHash; the next 32 bytes (64 chars)
    ///      must decode to bytes32(0). Reverts MaaJwtReportDataMalformed on wrong length or
    ///      non-hex characters; returns paddingZero=false to signal a non-zero padding (caller
    ///      reverts with the same error code).
    function _hexToReportData(string memory hexStr) private pure returns (bytes32 bindingHash, bool paddingZero) {
        bytes memory s = bytes(hexStr);
        if (s.length != 128) revert MaaJwtReportDataMalformed(s.length, type(uint256).max);

        uint256 acc;
        // First 64 chars → bindingHash
        for (uint256 i = 0; i < 64; i++) {
            acc = (acc << 4) | _hexDigit(uint8(s[i]), s.length, i);
        }
        bindingHash = bytes32(acc);

        // Next 64 chars → must decode to zero
        uint256 padAcc;
        for (uint256 i = 64; i < 128; i++) {
            padAcc = (padAcc << 4) | _hexDigit(uint8(s[i]), s.length, i);
        }
        paddingZero = (padAcc == 0);
    }

    /// @dev Returns the numeric value (0-15) of a single ASCII hex digit. Reverts on non-hex,
    ///      reporting the position of the offending character so callers can pinpoint it.
    function _hexDigit(uint8 c, uint256 strLen, uint256 pos) private pure returns (uint256) {
        unchecked {
            if (c >= 0x30 && c <= 0x39) return c - 0x30; // '0'-'9'
            if (c >= 0x61 && c <= 0x66) return c - 0x57; // 'a'-'f' → 10..15
            if (c >= 0x41 && c <= 0x46) return c - 0x37; // 'A'-'F' → 10..15
            revert MaaJwtReportDataMalformed(strLen, pos);
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
            akPubFingerprint: akPubFingerprint,
            // GCP certificate collateral does not authenticate a TEE type. SessionRegistry
            // ignores this field for GcpCertChain.
            teeType: TEEType.IntelTDX,
            bindingHash: bindingHash,
            amdSevSnpReportHash: bytes32(0),
            awsNitroRootCertHash: bytes32(0),
            qualifyingData: bytes32(0),
            documentTimestampSeconds: 0,
            sha384PcrSetCommitment: bytes32(0)
        });
    }

    function _verifyAwsNitroTpmCollateral(bytes calldata data, VerificationBackendType backend)
        private
        view
        returns (AkCollateralVerificationResult memory result)
    {
        ProgramBoundZkProof memory proof = abi.decode(data, (ProgramBoundZkProof));
        address adapter =
            zkVerifierRegistry.resolveVerifierAdapter(ZkProofType.AwsNitroTpm, backend, proof.programIdentifier);
        AwsNitroTpmJournalV1 memory journal = IAwsNitroTpmZkVerifierAdapter(adapter).verifyProof(proof);
        return AkCollateralVerificationResult({
            akPubFingerprint: journal.akPubFingerprint,
            teeType: TEEType.AmdSevSnp,
            bindingHash: bytes32(0),
            amdSevSnpReportHash: journal.amdSevSnpReportHash,
            awsNitroRootCertHash: journal.awsNitroRootCertHash,
            qualifyingData: journal.qualifyingData,
            documentTimestampSeconds: journal.documentTimestampSeconds,
            sha384PcrSetCommitment: journal.sha384PcrSetCommitment
        });
    }
}
