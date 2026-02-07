// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";
import {IDcapAttestation} from "./interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "./interfaces/external/ISnpAttestation.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {IBaseImageRegistry} from "./interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "./interfaces/registries/IWorkloadRegistry.sol";
import {ISessionRegistry, CVMSessionStorage} from "./interfaces/registries/ISessionRegistry.sol";
import {TeeVerifier, TeeVerificationResult} from "./bases/TeeVerifier.sol";
import {TpmVerifier, TpmQuoteVerificationResult, TpmCertifyVerificationResult, TpmBase} from "./bases/TpmVerifier.sol";
import {AkCollateralVerifier, AkCollateralVerificationResult} from "./bases/AkCollateralVerifier.sol";
import {
    CVMSession,
    PublicIdentity,
    PcrSpec,
    PcrVerifyType,
    Attribute,
    AttributeRequirement,
    WorkloadSpec,
    PlatformProfile,
    MeasurementVariant
} from "./types/Common.sol";
import {
    AttestationEvidence,
    TpmQuoteReport,
    TpmReport,
    AkPubCollateralType,
    TEEType,
    SessionRotationEvidence
} from "./types/Evidence.sol";
import {
    SESSION_DOMAIN,
    DELEGATION_DOMAIN,
    ROTATION_DOMAIN,
    SESSION_NONCE_DOMAIN,
    SESSION_REGISTER_MSG,
    SESSION_REVOKE_MSG,
    SESSION_ROTATE_MSG
} from "./types/Constants.sol";
import {LibKey} from "./lib/LibKey.sol";
import {LibBytes, Bytes48} from "./lib/LibBytes.sol";
import {Sha2Ext} from "./lib/Sha2Ext.sol";

/// @title SessionRegistry
/// @notice Central orchestrator for CVM session registration with 9-step attestation verification
/// @dev Inherits verification capabilities from TeeVerifier, TpmVerifier, and AkCollateralVerifier.
///      Coordinates with BaseImageRegistry and WorkloadRegistry to enforce platform and workload policies.
contract SessionRegistry is ISessionRegistry, TeeVerifier, TpmVerifier, AkCollateralVerifier {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════════════════════════════════════════

    uint64 internal constant DEFAULT_CVM_TTL = 30 days;
    /// @dev Offset of RTMR3 in TDX quote body (TD10/TD15)
    uint256 internal constant DCAP_RTMR3_OFFSET = 472;
    /// @dev Size of RTMR3 field (SHA-384 hash)
    uint256 internal constant DCAP_RTMR3_SIZE = 48;
    /// @dev Offset of reportData UUID in TDX quote body
    uint256 internal constant DCAP_REPORT_DATA_OFFSET = 520;
    /// @dev Offset of report_id in SNP attestation report
    uint256 internal constant SNP_REPORT_ID_OFFSET = 0x140;
    /// @dev Size of report_id field
    uint256 internal constant SNP_REPORT_ID_SIZE = 32;
    /// @dev PCR index used for GCP TEE-AK binding
    uint8 internal constant GCP_BINDING_PCR_INDEX = 15;
    /// @dev Size of UUID field
    uint256 internal constant GCP_UUID_SIZE = 16;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables - Registry Dependencies
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Signature verifier for owner authentication
    ISignatureVerifier public immutable signatureVerifier;

    /// @notice Base image registry for platform profile and variant lookups
    IBaseImageRegistry public immutable baseImageRegistry;

    /// @notice Workload registry for workload policy enforcement
    IWorkloadRegistry public immutable workloadRegistry;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Storage - Session State
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Session data storage
    mapping(bytes32 => CVMSessionStorage) private _sessions;

    /// @dev Owner nonce for replay protection
    mapping(bytes32 => uint256) private _ownerNonces;

    /// @dev Owner session list
    mapping(bytes32 => bytes32[]) private _ownerSessions;

    /// @dev Session fingerprint to session ID mapping
    mapping(bytes32 => bytes32) private _sessionFingerprintsToIds;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Invalid signature
    error InvalidSignature();

    /// @notice Signature expired
    error SignatureExpired();

    /// @notice Session already exists
    error SessionAlreadyExists();

    /// @notice Session not found
    error SessionNotFound();

    /// @notice Session not active
    error SessionNotActive();

    /// @notice Session already revoked
    error SessionAlreadyRevoked();

    /// @notice Unauthorized operation
    error Unauthorized();

    /// @notice TEE verification failed
    error TEEVerificationFailed();

    /// @notice AK collateral verification failed
    error AKCollateralVerificationFailed();

    /// @notice TEE-AK binding verification failed
    error TEEAKBindingFailed();

    /// @notice TPM quote verification failed
    error TPMQuoteVerificationFailed();

    /// @notice TPM certify verification failed
    error TPMCertifyVerificationFailed();

    /// @notice Session key delegation verification failed
    error SessionKeyDelegationFailed();

    /// @notice PCR verification failed
    error PCRVerificationFailed();

    /// @notice PCR not found in quote
    error PCRNotFound();

    /// @notice Attribute not found
    error AttributeNotFound(bytes32 key);

    /// @notice Attribute value not allowed
    error AttributeValueNotAllowed(bytes32 key);

    /// @notice Workload not active
    error WorkloadNotActive(bytes32 workloadId);

    /// @notice Base image not active
    error BaseImageNotActive(bytes32 baseImageId);

    /// @notice Base image not allowed for workload
    error BaseImageNotAllowed(bytes32 baseImageId);

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Initializes SessionRegistry with all dependency contracts
    /// @param _dcapAttestation DCAP attestation verifier for Intel TDX
    /// @param _snpAttestation SNP attestation verifier for AMD SEV-SNP
    /// @param _tpmAttestation TPM attestation verifier from automata-tpm-attestation
    /// @param _signatureVerifier Signature verifier for owner authentication
    /// @param _baseImageRegistry Base image registry for platform profiles
    /// @param _workloadRegistry Workload registry for workload policies
    constructor(
        IDcapAttestation _dcapAttestation,
        ISnpAttestation _snpAttestation,
        ITpmAttestation _tpmAttestation,
        ISignatureVerifier _signatureVerifier,
        IBaseImageRegistry _baseImageRegistry,
        IWorkloadRegistry _workloadRegistry
    ) TeeVerifier(_dcapAttestation, _snpAttestation) TpmBase(_tpmAttestation) {
        signatureVerifier = _signatureVerifier;
        baseImageRegistry = _baseImageRegistry;
        workloadRegistry = _workloadRegistry;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Registration
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function registerSession(
        AttestationEvidence calldata evidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 variantId,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 sessionId) {
        // ─────────────────────────────────────────────────────────────────────────────────
        // Preliminary: Signature Expiry Check
        // ─────────────────────────────────────────────────────────────────────────────────
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 1: Policy Lookup
        // ─────────────────────────────────────────────────────────────────────────────────
        PolicyContext memory policyCtx = _lookupPolicy(workloadId, baseImageId, platformProfileId, variantId);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEPS 2-5: Attestation Verification Chain
        // ─────────────────────────────────────────────────────────────────────────────────
        AttestationResult memory attestationResult = _verifyAttestation(evidence, ownerIdentity);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 6: Session ID Computation + Session Key Delegation
        // ─────────────────────────────────────────────────────────────────────────────────
        bytes32 teeReportBytesHash = keccak256(evidence.teeReport.data);
        sessionId = _computeSessionId(attestationResult.tpmSignatureHash, teeReportBytesHash);

        if (_sessions[sessionId].exists) {
            revert SessionAlreadyExists();
        }

        bytes32 sessionKeyFingerprint = _verifySessionKeyDelegation(
            attestationResult.certifiedKey,
            evidence.sessionKeySignature,
            evidence.sessionKey,
            baseImageId,
            workloadId,
            sessionId
        );

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEPS 7-8: Policy Evaluation (PCR + Attributes)
        // ─────────────────────────────────────────────────────────────────────────────────
        _evaluatePolicy(
            attestationResult.pcrValues,
            policyCtx.platformProfile,
            policyCtx.variant,
            policyCtx.workloadSpec,
            attestationResult.expectedPcr15
        );

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 9: Owner Signature Verification + Session Creation
        // ─────────────────────────────────────────────────────────────────────────────────

        // Verify owner signature over session registration message
        bytes32 message = sha256(abi.encode(SESSION_REGISTER_MSG, block.chainid, address(this), expireAt, sessionId));
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Create session with TTL handling (default: 30 days)
        uint64 expiresAt = policyCtx.workloadSpec.ttl == 0
            ? uint64(block.timestamp) + DEFAULT_CVM_TTL
            : uint64(block.timestamp) + policyCtx.workloadSpec.ttl;

        _createSession(
            SessionParams({
                sessionId: sessionId,
                ownerFingerprint: attestationResult.ownerFingerprint,
                akPubKeyFingerprint: attestationResult.akPubFingerprint,
                tpmSigningKeyFingerprint: attestationResult.tpmSigningKeyFingerprint,
                sessionKeyFingerprint: sessionKeyFingerprint,
                baseImageId: baseImageId,
                workloadId: workloadId,
                platformProfileId: platformProfileId,
                measurementVariantId: variantId,
                expiresAt: expiresAt
            })
        );

        // Emit events
        emit SessionRegistered(
            sessionId,
            attestationResult.ownerFingerprint,
            workloadId,
            baseImageId,
            attestationResult.akPubFingerprint,
            attestationResult.tpmSigningKeyFingerprint,
            sessionKeyFingerprint
        );

        emit AttestationKeysRevealed(
            sessionId, attestationResult.akPub, attestationResult.certifiedKey, evidence.sessionKey
        );

        return sessionId;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Revocation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function revokeSession(
        bytes32 sessionId,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check expiry first
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        // Check session exists
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];
        if (!sessionStorage.exists) {
            revert SessionNotFound();
        }

        // Check session is active
        if (sessionStorage.isRevoked) {
            revert SessionAlreadyRevoked();
        }

        // Verify owner fingerprint
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (sessionStorage.owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Verify signature
        bytes32 message = sha256(abi.encode(SESSION_REVOKE_MSG, block.chainid, address(this), expireAt, sessionId));

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Revoke session
        sessionStorage.isRevoked = true;

        emit SessionRevoked(sessionId, ownerFingerprint);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Rotation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function rotateSession(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionRotationEvidence calldata rotationEvidence,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId) {
        return _rotateSession(
            oldSessionId, teeReportBytesHash, rotationEvidence, expireAt, ownerIdentity, ownerSignature
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - View Functions
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function getSession(bytes32 sessionId) external view returns (CVMSession memory session) {
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];
        if (!sessionStorage.exists) {
            revert SessionNotFound();
        }
        return sessionStorage.session;
    }

    function getSessionId(bytes32 sessionFingerprint) external view returns (bytes32 sessionId) {
        return _sessionFingerprintsToIds[sessionFingerprint];
    }

    /// @inheritdoc ISessionRegistry
    function isSessionActive(bytes32 sessionId) external view returns (bool) {
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];
        if (!sessionStorage.exists) {
            return false;
        }
        return sessionStorage.exists && !sessionStorage.isRevoked && block.timestamp <= sessionStorage.session.expiresAt;
    }

    /// @inheritdoc ISessionRegistry
    function isSessionExpired(bytes32 sessionId) external view returns (bool) {
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];
        if (!sessionStorage.exists) {
            return false;
        }
        return block.timestamp > sessionStorage.session.expiresAt;
    }

    /// @inheritdoc ISessionRegistry
    function getOwnerSessions(bytes32 ownerFingerprint) external view returns (bytes32[] memory) {
        return _ownerSessions[ownerFingerprint];
    }

    /// @inheritdoc ISessionRegistry
    function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce) {
        return _ownerNonces[ownerFingerprint];
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Structs
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Policy context result from policy lookup
    struct PolicyContext {
        PlatformProfile platformProfile;
        MeasurementVariant variant;
        WorkloadSpec workloadSpec;
    }

    /// @dev Session parameters for session creation
    struct SessionParams {
        bytes32 sessionId;
        bytes32 ownerFingerprint;
        bytes32 akPubKeyFingerprint;
        bytes32 tpmSigningKeyFingerprint;
        bytes32 sessionKeyFingerprint;
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 expiresAt;
    }

    /// @dev Internal struct to pass attestation results between internal functions
    struct AttestationResult {
        PublicIdentity akPub;
        PublicIdentity certifiedKey;
        bytes32 akPubFingerprint;
        bytes32 tpmSigningKeyFingerprint;
        bytes32 ownerFingerprint;
        PcrValue[] pcrValues;
        bytes32 expectedPcr15; // GCP binding PCR15 expected value (zero for Azure)
        bytes32 tpmSignatureHash; // Hash of TPM quote signature (for session ID computation)
    }

    /// @dev Rotation context derived from the old session
    struct RotationContext {
        bytes32 ownerFingerprint;
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 expiresAt;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Session Rotation Helpers
    // ═══════════════════════════════════════════════════════════════════════════════════════

    function _rotateSession(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionRotationEvidence calldata evidence,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) internal returns (bytes32 newSessionId) {
        RotationContext memory ctx = _loadRotationContext(
            oldSessionId, evidence.oldTpmSigningKey, evidence.akPub, ownerIdentity
        );

        (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash) =
            _verifyTpmQuoteWithNonce(evidence.tpmQuoteReport, evidence.akPub, ctx.ownerFingerprint);

        (PublicIdentity memory newTpmSigningKey, bytes32 newTpmSigningKeyFingerprint) =
            _verifyCertifiedKey(evidence.tpmCertifyReport, evidence.akPub);

        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(evidence.sessionKey);

        _verifyRotationAuthorization(
            oldSessionId,
            newTpmSigningKeyFingerprint,
            sessionKeyFingerprint,
            teeReportBytesHash,
            evidence.rotationSignature,
            evidence.oldTpmSigningKey
        );

        newSessionId = _computeSessionId(tpmSignatureHash, teeReportBytesHash);
        if (_sessions[newSessionId].exists) {
            revert SessionAlreadyExists();
        }

        sessionKeyFingerprint = _verifySessionKeyDelegation(
            newTpmSigningKey,
            evidence.sessionKeySignature,
            evidence.sessionKey,
            ctx.baseImageId,
            ctx.workloadId,
            newSessionId
        );

        PolicyContext memory policyCtx =
            _lookupPolicy(ctx.workloadId, ctx.baseImageId, ctx.platformProfileId, ctx.measurementVariantId);

        // No TEE re-attestation during rotation; skip GCP PCR15 binding check
        _evaluatePolicy(pcrValues, policyCtx.platformProfile, policyCtx.variant, policyCtx.workloadSpec, bytes32(0));

        _finalizeRotation(
            oldSessionId,
            newSessionId,
            newTpmSigningKeyFingerprint,
            sessionKeyFingerprint,
            newTpmSigningKey,
            ctx,
            expireAt,
            ownerIdentity,
            ownerSignature,
            evidence.akPub,
            evidence.sessionKey
        );

        return newSessionId;
    }

    function _loadRotationContext(
        bytes32 oldSessionId,
        PublicIdentity calldata oldTpmSigningKey,
        PublicIdentity calldata akPub,
        PublicIdentity calldata ownerIdentity
    ) internal view returns (RotationContext memory ctx) {
        CVMSessionStorage storage oldSessionStorage = _sessions[oldSessionId];
        if (!oldSessionStorage.exists) {
            revert SessionNotFound();
        }

        if (oldSessionStorage.isRevoked) {
            revert SessionAlreadyRevoked();
        }

        if (block.timestamp > oldSessionStorage.session.expiresAt) {
            revert SessionNotActive();
        }

        bytes32 oldTpmSigningKeyFingerprint = LibKey.computeKeyFingerprint(oldTpmSigningKey);
        if (oldTpmSigningKeyFingerprint != oldSessionStorage.session.tpmSigningKeyFingerprint) {
            revert Unauthorized();
        }

        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(akPub);
        if (akPubFingerprint != oldSessionStorage.session.akPubKeyFingerprint) {
            revert Unauthorized();
        }

        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (ownerFingerprint != oldSessionStorage.owner) {
            revert Unauthorized();
        }

        return RotationContext({
            ownerFingerprint: ownerFingerprint,
            baseImageId: oldSessionStorage.session.baseImageId,
            workloadId: oldSessionStorage.session.workloadId,
            platformProfileId: oldSessionStorage.session.platformProfileId,
            measurementVariantId: oldSessionStorage.session.measurementVariantId,
            expiresAt: oldSessionStorage.session.expiresAt
        });
    }

    function _finalizeRotation(
        bytes32 oldSessionId,
        bytes32 newSessionId,
        bytes32 newTpmSigningKeyFingerprint,
        bytes32 sessionKeyFingerprint,
        PublicIdentity memory newTpmSigningKey,
        RotationContext memory ctx,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature,
        PublicIdentity calldata akPub,
        PublicIdentity calldata sessionKey
    ) internal {
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }

        bytes32 message =
            sha256(abi.encode(SESSION_ROTATE_MSG, block.chainid, address(this), expireAt, oldSessionId, newSessionId));

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        _sessions[oldSessionId].isRevoked = true;

        _createSession(
            SessionParams({
                sessionId: newSessionId,
                ownerFingerprint: ctx.ownerFingerprint,
                akPubKeyFingerprint: _sessions[oldSessionId].session.akPubKeyFingerprint,
                tpmSigningKeyFingerprint: newTpmSigningKeyFingerprint,
                sessionKeyFingerprint: sessionKeyFingerprint,
                baseImageId: ctx.baseImageId,
                workloadId: ctx.workloadId,
                platformProfileId: ctx.platformProfileId,
                measurementVariantId: ctx.measurementVariantId,
                expiresAt: ctx.expiresAt
            })
        );

        emit SessionRotated(
            oldSessionId, newSessionId, ctx.ownerFingerprint, newTpmSigningKeyFingerprint, sessionKeyFingerprint
        );

        emit AttestationKeysRevealed(newSessionId, akPub, newTpmSigningKey, sessionKey);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Attestation Verification (Steps 2-5)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Executes Steps 2-5 of the verification workflow
    /// @param evidence The attestation evidence bundle
    /// @param ownerIdentity The owner's public identity (for nonce binding)
    /// @return result Attestation verification results
    function _verifyAttestation(AttestationEvidence calldata evidence, PublicIdentity calldata ownerIdentity)
        internal
        returns (AttestationResult memory result)
    {
        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 2: TEE Report Verification
        // ─────────────────────────────────────────────────────────────────────────────────
        TeeVerificationResult memory teeResult = verifyTeeReport(evidence.teeReport);
        if (!teeResult.valid) {
            revert TEEVerificationFailed();
        }

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 3: AK Collateral + TEE↔vTPM Binding
        // ─────────────────────────────────────────────────────────────────────────────────
        AkCollateralVerificationResult memory akResult = verifyAkCollateral(evidence.akPubCollateral);
        if (!akResult.valid) {
            revert AKCollateralVerificationFailed();
        }

        // Verify TEE-AK binding and get expected PCR15 for GCP
        bytes32 expectedPcr15 = _verifyTeeAkBinding(teeResult, akResult, evidence);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 4: TPM Quote Verification
        // ─────────────────────────────────────────────────────────────────────────────────
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash) =
            _verifyTpmQuoteWithNonce(evidence.tpmQuoteReport, akResult.akPub, ownerFingerprint);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 5: TPM Certify Verification
        // ─────────────────────────────────────────────────────────────────────────────────
        (PublicIdentity memory certifiedKey, bytes32 tpmSigningKeyFingerprint) =
            _verifyCertifiedKey(evidence.tpmCertifyReport, akResult.akPub);

        return AttestationResult({
            akPub: akResult.akPub,
            certifiedKey: certifiedKey,
            ownerFingerprint: ownerFingerprint,
            akPubFingerprint: akResult.akPubFingerprint,
            tpmSigningKeyFingerprint: tpmSigningKeyFingerprint,
            pcrValues: pcrValues,
            expectedPcr15: expectedPcr15,
            tpmSignatureHash: tpmSignatureHash
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Session ID Computation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Computes the domain-separated session ID from signature hashes
    function _computeSessionId(bytes32 tpmSignatureHash, bytes32 teeReportBytesHash)
        internal
        pure
        returns (bytes32 sessionId)
    {
        return keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash));
    }

    /// @dev Looks up and validates policy components (workload, base image, variant)
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The measurement variant identifier
    /// @return ctx Policy context containing platform profile, variant, and workload spec
    function _lookupPolicy(bytes32 workloadId, bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        internal
        view
        returns (PolicyContext memory ctx)
    {
        if (workloadRegistry.isWorkloadRevoked(workloadId)) {
            revert WorkloadNotActive(workloadId);
        }

        if (baseImageRegistry.isBaseImageRevoked(baseImageId)) {
            revert BaseImageNotActive(baseImageId);
        }

        if (!workloadRegistry.isBaseImageAllowed(workloadId, baseImageId)) {
            revert BaseImageNotAllowed(baseImageId);
        }

        (, PlatformProfile memory platformProfile, MeasurementVariant memory variant) =
            baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId);

        WorkloadSpec memory workloadSpec = workloadRegistry.getWorkload(workloadId);

        return PolicyContext({platformProfile: platformProfile, variant: variant, workloadSpec: workloadSpec});
    }

    /// @dev Verifies TPM quote with owner nonce binding
    /// @param tpmQuoteReport The TPM quote report
    /// @param akPub The attestation key public identity
    /// @param ownerFingerprint The owner's fingerprint for nonce lookup
    /// @return pcrValues The PCR values from the quote
    /// @return tpmSignatureHash The hash of the TPM signature
    function _verifyTpmQuoteWithNonce(
        TpmReport memory tpmQuoteReport,
        PublicIdentity memory akPub,
        bytes32 ownerFingerprint
    ) internal returns (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash) {
        uint256 nonce = _ownerNonces[ownerFingerprint];
        bytes32 expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce));

        TpmQuoteVerificationResult memory quoteResult = verifyTpmQuote(tpmQuoteReport, akPub, expectedExtraData);

        if (!quoteResult.valid) {
            revert TPMQuoteVerificationFailed();
        }

        // Increment nonce immediately after successful verification to prevent replay attacks
        _ownerNonces[ownerFingerprint] += 1;

        TpmQuoteReport memory quoteReport = abi.decode(tpmQuoteReport.data, (TpmQuoteReport));
        return (quoteResult.pcrValues, keccak256(quoteReport.tpmSignature));
    }

    /// @dev Verifies TPM certify and extracts the certified key
    /// @param tpmCertifyReport The TPM certify report
    /// @param akPub The attestation key public identity
    /// @return certifiedKey The certified key (TPM signing key)
    /// @return certifiedKeyFingerprint The fingerprint of the certified key
    function _verifyCertifiedKey(TpmReport memory tpmCertifyReport, PublicIdentity memory akPub)
        internal
        view
        returns (PublicIdentity memory certifiedKey, bytes32 certifiedKeyFingerprint)
    {
        TpmCertifyVerificationResult memory certifyResult = verifyTpmCertify(tpmCertifyReport, akPub);

        if (!certifyResult.valid) {
            revert TPMCertifyVerificationFailed();
        }

        return (certifyResult.certifiedKey, certifyResult.certifiedKeyFingerprint);
    }

    /// @dev Verifies session key delegation signature
    /// @param certifiedKey The certified TPM signing key
    /// @param sessionKeySignature The delegation signature
    /// @param sessionKey The session key being delegated to
    /// @param baseImageId The base image identifier
    /// @param workloadId The workload identifier
    /// @param sessionId The session identifier
    /// @return sessionKeyFingerprint The fingerprint of the session key
    function _verifySessionKeyDelegation(
        PublicIdentity memory certifiedKey,
        bytes memory sessionKeySignature,
        PublicIdentity memory sessionKey,
        bytes32 baseImageId,
        bytes32 workloadId,
        bytes32 sessionId
    ) internal view returns (bytes32 sessionKeyFingerprint) {
        sessionKeyFingerprint = LibKey.computeKeyFingerprint(sessionKey);

        bytes32 delegationMessage =
            keccak256(abi.encode(DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint));

        if (!signatureVerifier.verify(certifiedKey, delegationMessage, sessionKeySignature)) {
            revert SessionKeyDelegationFailed();
        }

        return sessionKeyFingerprint;
    }

    /// @dev Verifies rotation authorization signature (rotation-specific step)
    /// @param oldSessionId The old session identifier
    /// @param certifiedKeyFingerprint The fingerprint of the new TPM signing key
    /// @param sessionKeyFingerprint The fingerprint of the session key
    /// @param teeReportBytesHash The hash of the TEE report
    /// @param rotationSignature The rotation authorization signature
    /// @param oldTpmSigningKey The old TPM signing key (must sign the rotation)
    function _verifyRotationAuthorization(
        bytes32 oldSessionId,
        bytes32 certifiedKeyFingerprint,
        bytes32 sessionKeyFingerprint,
        bytes32 teeReportBytesHash,
        bytes memory rotationSignature,
        PublicIdentity memory oldTpmSigningKey
    ) internal view {
        bytes32 rotationMessage = keccak256(
            abi.encode(
                ROTATION_DOMAIN, oldSessionId, certifiedKeyFingerprint, sessionKeyFingerprint, teeReportBytesHash
            )
        );

        if (!signatureVerifier.verify(oldTpmSigningKey, rotationMessage, rotationSignature)) {
            revert InvalidSignature();
        }
    }

    /// @dev Creates a new session and updates related storage
    /// @param params Session parameters for the new session
    function _createSession(SessionParams memory params) internal {
        _sessions[params.sessionId] = CVMSessionStorage({
            exists: true,
            isRevoked: false,
            owner: params.ownerFingerprint,
            session: CVMSession({
                akPubKeyFingerprint: params.akPubKeyFingerprint,
                tpmSigningKeyFingerprint: params.tpmSigningKeyFingerprint,
                sessionKeyFingerprint: params.sessionKeyFingerprint,
                baseImageId: params.baseImageId,
                workloadId: params.workloadId,
                platformProfileId: params.platformProfileId,
                measurementVariantId: params.measurementVariantId,
                registeredAt: uint64(block.timestamp),
                expiresAt: params.expiresAt
            })
        });

        _sessionFingerprintsToIds[params.sessionKeyFingerprint] = params.sessionId;

        _ownerSessions[params.ownerFingerprint].push(params.sessionId);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Policy Evaluation (Steps 7-8)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Executes Steps 7-8: PCR and attribute policy evaluation
    /// @param pcrValues The PCR values from TPM quote
    /// @param platformProfile The platform profile (invariants + attributes)
    /// @param variant The measurement variant (overrides + attributes)
    /// @param workloadSpec The workload specification (pcrs + requirements)
    /// @param expectedPcr15 Expected PCR15 value for GCP binding (zero for Azure)
    function _evaluatePolicy(
        PcrValue[] memory pcrValues,
        PlatformProfile memory platformProfile,
        MeasurementVariant memory variant,
        WorkloadSpec memory workloadSpec,
        bytes32 expectedPcr15
    ) internal pure {
        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 7: PCR Policy Evaluation
        // ─────────────────────────────────────────────────────────────────────────────────

        // Merge platform profile invariants with variant overrides
        PcrSpec[] memory effectivePcrs = _mergePcrSpecs(platformProfile.invariants, variant.overridePcrs);

        // Evaluate effective PCR specs (platform + variant)
        _evaluatePcrSpecs(effectivePcrs, pcrValues);

        // Evaluate workload PCR specs
        _evaluatePcrSpecs(workloadSpec.pcrs, pcrValues);

        // GCP PCR15 binding check (if applicable)
        if (expectedPcr15 != bytes32(0)) {
            // Find PCR15 in measured values
            PcrValue memory measuredPcr15 = _findPcrValue(pcrValues, GCP_BINDING_PCR_INDEX);

            // Verify PCR15 matches expected value
            if (measuredPcr15.value != expectedPcr15) {
                revert PCRVerificationFailed();
            }
        }

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 8: Attribute Requirements Evaluation
        // ─────────────────────────────────────────────────────────────────────────────────

        // Merge platform profile attributes with variant attributes (variant overrides)
        Attribute[] memory effectiveAttributes = _mergeAttributes(platformProfile.attributes, variant.attributes);

        // Evaluate workload attribute requirements
        _evaluateAttributeRequirements(workloadSpec.requirements, effectiveAttributes);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Helpers - TEE-AK Binding
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies TEE-AK binding based on cloud provider and TEE type
    /// @param teeResult TEE verification result (contains reportData)
    /// @param akResult AK collateral verification result (contains bindingHash)
    /// @param evidence Attestation evidence bundle
    /// @return expectedPcr15 Expected PCR15 value for GCP binding (zero for Azure)
    function _verifyTeeAkBinding(
        TeeVerificationResult memory teeResult,
        AkCollateralVerificationResult memory akResult,
        AttestationEvidence calldata evidence
    ) internal pure returns (bytes32 expectedPcr15) {
        if (evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AzureAkPubJson) {
            // Azure binding: reportData[0:32] == sha256(akCollateral.data)
            bytes memory reportData = extractDcapReportData(teeResult.reportData);

            bytes32 reportDataHash;
            bytes32 reportDataPadding;
            assembly ("memory-safe") {
                reportDataHash := mload(add(reportData, 0x20))
                reportDataPadding := mload(add(reportData, 0x40))
            }

            // first 32 bytes is hash, next 32 bytes should be zero padding
            if (reportDataHash != akResult.bindingHash || reportDataPadding != bytes32(0)) {
                revert TEEAKBindingFailed();
            }

            return bytes32(0); // No PCR15 binding for Azure
        } else if (evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.GcpCertChain) {
            // GCP binding: different logic based on TEE type
            if (teeResult.teeType == TEEType.IntelTDX) {
                // GCP-TDX: verify RTMR3 and compute expected PCR15
                return _verifyGcpTdxBinding(teeResult.reportData);
            } else if (teeResult.teeType == TEEType.AmdSevSnp) {
                // GCP-SNP: compute expected PCR15 from report_id
                return _verifyGcpSnpBinding(teeResult.reportData);
            } else {
                revert TEEAKBindingFailed();
            }
        } else {
            revert TEEAKBindingFailed();
        }
    }

    /// @dev Verifies RTMR3 binding and computes expected PCR15 for GCP-TDX
    /// @param quoteBody The TDX quote body (584 or 648 bytes)
    /// @return expectedPcr15 Expected PCR15 value
    function _verifyGcpTdxBinding(bytes memory quoteBody) internal pure returns (bytes32 expectedPcr15) {
        // Extract UUID (16 bytes) from reportData at offset 520
        bytes memory uuidBytes = LibBytes.slice(quoteBody, DCAP_REPORT_DATA_OFFSET, GCP_UUID_SIZE);

        // ── RTMR3 Verification ──────────────────────────────────────────────
        // Extract actual RTMR3 (48 bytes) from quote body at offset 472
        Bytes48 memory actualRtmr3 = LibBytes.readBytes48(quoteBody, DCAP_RTMR3_OFFSET);

        // Compute expected RTMR3 = sha384( bytes48(0) || sha384(UUID) )
        Bytes48 memory uuidHash = Sha2Ext.sha384(uuidBytes);
        Bytes48 memory expectedRtmr3 = Sha2Ext.sha384(
            abi.encodePacked(
                new bytes(48), // 48 zero bytes
                uuidHash.first,
                uuidHash.second // 48-byte inner hash
            )
        );

        if (!LibBytes.equal(actualRtmr3, expectedRtmr3)) {
            revert TEEAKBindingFailed();
        }

        // ── PCR15 Computation (unchanged) ────────────────────────────────────
        bytes32 innerPcr = sha256(uuidBytes);
        expectedPcr15 = sha256(abi.encodePacked(bytes32(0), innerPcr));

        return expectedPcr15;
    }

    /// @dev Verifies GCP-SNP binding and computes expected PCR15
    /// @param rawReport The SNP attestation report
    /// @return expectedPcr15 Expected PCR15 value
    function _verifyGcpSnpBinding(bytes memory rawReport) internal pure returns (bytes32 expectedPcr15) {
        // Extract report_id (32 bytes) from SNP report at offset 0x140
        bytes32 reportId = LibBytes.readBytes32(rawReport, SNP_REPORT_ID_OFFSET);

        // Compute expected PCR15 = sha256(bytes32(0) || report_id)
        expectedPcr15 = sha256(abi.encodePacked(bytes32(0), reportId));

        return expectedPcr15;
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Helpers - PCR Evaluation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Merges platform invariants with variant overrides (variant replaces at matching pcrIndex)
    /// @param invariants Platform profile invariants
    /// @param overrides Variant PCR overrides
    /// @return merged Effective PCR specifications
    function _mergePcrSpecs(PcrSpec[] memory invariants, PcrSpec[] memory overrides)
        internal
        pure
        returns (PcrSpec[] memory merged)
    {
        // Max PCR indices are 0..23, so allocate once and compact later
        merged = new PcrSpec[](24);

        uint256 overrideMask = 0;
        uint256 presentMask = 0;

        // Apply overrides while building overrideMask
        for (uint256 i = 0; i < overrides.length; i++) {
            uint256 idx = uint256(overrides[i].pcrIndex);
            uint256 bit = (uint256(1) << idx);
            overrideMask |= bit;

            merged[idx] = overrides[i];
            presentMask |= bit;
        }

        // Insert invariants that are not overridden
        for (uint256 i = 0; i < invariants.length; i++) {
            uint256 idx = uint256(invariants[i].pcrIndex);
            uint256 bit = (uint256(1) << idx);
            if ((overrideMask & bit) == 0) {
                merged[idx] = invariants[i];
                presentMask |= bit;
            }
        }

        // Compact into sorted order by pcrIndex
        uint256 writeIdx = 0;
        for (uint256 idx = 0; idx < 24; idx++) {
            if ((presentMask & (uint256(1) << idx)) != 0) {
                if (writeIdx != idx) {
                    merged[writeIdx] = merged[idx];
                }
                writeIdx++;
            }
        }

        assembly ("memory-safe") {
            mstore(merged, writeIdx)
        }

        return merged;
    }

    /// @dev Evaluates all PCR specs against measured PCR values
    /// @param specs PCR specifications to evaluate (sorted by pcrIndex)
    /// @param pcrValues Measured PCR values from TPM quote (sorted by pcrIndex)
    function _evaluatePcrSpecs(PcrSpec[] memory specs, PcrValue[] memory pcrValues) internal pure {
        uint256 i = 0;
        uint256 j = 0;

        while (i < specs.length && j < pcrValues.length) {
            uint8 specIdx = specs[i].pcrIndex;
            uint8 measuredIdx = pcrValues[j].pcrIndex;

            if (measuredIdx == specIdx) {
                _evaluateSinglePcr(specs[i], pcrValues[j]);
                i++;
                j++;
            } else if (measuredIdx < specIdx) {
                // Measured PCR not required by spec, skip it
                j++;
            } else {
                // Spec PCR missing from measured set
                revert PCRNotFound();
            }
        }

        if (i < specs.length) {
            revert PCRNotFound();
        }
    }

    /// @dev Finds a PCR value by index in the measured PCR values array
    /// @param pcrValues Measured PCR values from TPM quote
    /// @param pcrIndex PCR index to find
    /// @return pcr The PCR value (reverts if not found)
    function _findPcrValue(PcrValue[] memory pcrValues, uint8 pcrIndex) internal pure returns (PcrValue memory pcr) {
        for (uint256 i = 0; i < pcrValues.length; i++) {
            if (pcrValues[i].pcrIndex == pcrIndex) {
                return pcrValues[i];
            }
        }
        revert PCRNotFound();
    }

    /// @dev Evaluates a single PCR spec against a measured PCR value
    /// @param spec PCR specification
    /// @param measured Measured PCR value
    function _evaluateSinglePcr(PcrSpec memory spec, PcrValue memory measured) internal pure {
        if (spec.verifyType == PcrVerifyType.STATIC) {
            // STATIC: exact value match
            if (measured.value != spec.matchData[0]) {
                revert PCRVerificationFailed();
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSET) {
            // DYNAMIC_SUBSET: eventLogHashes ⊆ matchData
            for (uint256 i = 0; i < measured.eventLogHashes.length; i++) {
                bool found = false;
                for (uint256 j = 0; j < spec.matchData.length; j++) {
                    if (measured.eventLogHashes[i] == spec.matchData[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    revert PCRVerificationFailed();
                }
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSEQUENCE) {
            // DYNAMIC_SUBSEQUENCE: matchData is subsequence of eventLogHashes
            uint256 matchIdx = 0;
            for (uint256 i = 0; i < measured.eventLogHashes.length && matchIdx < spec.matchData.length; i++) {
                if (measured.eventLogHashes[i] == spec.matchData[matchIdx]) {
                    matchIdx++;
                }
            }
            if (matchIdx != spec.matchData.length) {
                revert PCRVerificationFailed();
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Helpers - Attribute Evaluation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Merges platform profile attributes with variant attributes (variant overrides at matching keys)
    /// @param profileAttrs Platform profile attributes
    /// @param variantAttrs Variant attributes
    /// @return merged Effective attributes
    /// TODO: unionize platform and variant attributes
    function _mergeAttributes(Attribute[] memory profileAttrs, Attribute[] memory variantAttrs)
        internal
        pure
        returns (Attribute[] memory merged)
    {
        // Allocate max-size array (worst case: no overlaps)
        merged = new Attribute[](profileAttrs.length + variantAttrs.length);
        uint256 writeIdx = 0;

        // Single-pass: add profile attributes that are not overridden
        for (uint256 i = 0; i < profileAttrs.length; i++) {
            bool overridden = false;
            for (uint256 j = 0; j < variantAttrs.length; j++) {
                if (profileAttrs[i].key == variantAttrs[j].key) {
                    overridden = true;
                    break;
                }
            }
            if (!overridden) {
                merged[writeIdx] = profileAttrs[i];
                writeIdx++;
            }
        }

        // Add all variant attributes
        for (uint256 i = 0; i < variantAttrs.length; i++) {
            merged[writeIdx] = variantAttrs[i];
            writeIdx++;
        }

        // Trim array to actual size using assembly
        assembly ("memory-safe") {
            mstore(merged, writeIdx)
        }

        return merged;
    }

    /// @dev Evaluates workload attribute requirements against effective attributes
    /// @param requirements Workload attribute requirements
    /// @param attributes Effective attributes (merged platform + variant)
    function _evaluateAttributeRequirements(AttributeRequirement[] memory requirements, Attribute[] memory attributes)
        internal
        pure
    {
        for (uint256 i = 0; i < requirements.length; i++) {
            // Find attribute by key
            bool found = false;
            bytes32 attributeValue;

            for (uint256 j = 0; j < attributes.length; j++) {
                if (attributes[j].key == requirements[i].key) {
                    found = true;
                    attributeValue = attributes[j].value;
                    break;
                }
            }

            if (!found) {
                revert AttributeNotFound(requirements[i].key);
            }

            // Check allowedValues (empty array = any value accepted)
            if (requirements[i].allowedValues.length > 0) {
                bool valueAllowed = false;
                for (uint256 k = 0; k < requirements[i].allowedValues.length; k++) {
                    if (attributeValue == requirements[i].allowedValues[k]) {
                        valueAllowed = true;
                        break;
                    }
                }
                if (!valueAllowed) {
                    revert AttributeValueNotAllowed(requirements[i].key);
                }
            }
        }
    }
}
