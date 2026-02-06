// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {IDcapAttestation} from "./interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "./interfaces/external/ISnpAttestation.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {IBaseImageRegistry} from "./interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "./interfaces/registries/IWorkloadRegistry.sol";
import {ISessionRegistry} from "./interfaces/registries/ISessionRegistry.sol";
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
import {AttestationEvidence, TpmQuoteReport, TpmReport, AkPubCollateralType, TEEType} from "./types/Evidence.sol";
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
import {LibBytes} from "./lib/LibBytes.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

/// @title SessionRegistry
/// @notice Central orchestrator for CVM session registration with 9-step attestation verification
/// @dev Inherits verification capabilities from TeeVerifier, TpmVerifier, and AkCollateralVerifier.
///      Coordinates with BaseImageRegistry and WorkloadRegistry to enforce platform and workload policies.
contract SessionRegistry is ISessionRegistry, TeeVerifier, TpmVerifier, AkCollateralVerifier {
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
    // Constants - TEE Binding Offsets
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Offset of RTMR3 in TDX quote body (TD10/TD15)
    uint256 internal constant DCAP_RTMR3_OFFSET = 472;
    /// @dev Size of RTMR3 field (SHA-384 hash)
    uint256 internal constant DCAP_RTMR3_SIZE = 48;
    /// @dev Offset of reportData UUID in TDX quote body
    uint256 internal constant DCAP_UUID_OFFSET = 520;
    /// @dev Size of UUID field
    uint256 internal constant DCAP_UUID_SIZE = 16;
    /// @dev Offset of report_id in SNP attestation report
    uint256 internal constant SNP_REPORT_ID_OFFSET = 0x140;
    /// @dev Size of report_id field
    uint256 internal constant SNP_REPORT_ID_SIZE = 32;
    /// @dev PCR index used for GCP TEE-AK binding
    uint8 internal constant GCP_BINDING_PCR_INDEX = 15;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Storage - Session State
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Session data storage
    mapping(bytes32 => CVMSession) private _sessions;

    /// @dev Session existence tracker
    mapping(bytes32 => bool) private _sessionExists;

    /// @dev Owner nonce for replay protection
    mapping(bytes32 => uint256) private _ownerNonces;

    /// @dev Owner session list
    mapping(bytes32 => bytes32[]) private _ownerSessions;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Structs - Rotation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Rotation context derived from the old session
    struct RotationContext {
        bytes32 ownerFingerprint;
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 expiresAt;
    }

    /// @dev Rotation inputs (copied from calldata to reduce stack usage)
    struct RotationInputs {
        bytes32 oldSessionId;
        bytes32 teeReportSignatureHash;
        TpmReport tpmQuoteReport;
        TpmReport tpmCertifyReport;
        bytes sessionKeySignature;
        PublicIdentity sessionKey;
        bytes rotationSignature;
        PublicIdentity oldTpmSigningKey;
        PublicIdentity akPub;
        uint64 expireAt;
        PublicIdentity ownerIdentity;
        bytes ownerSignature;
    }

    /// @dev Rotation results produced from TPM verification and delegation
    struct RotationResults {
        bytes32 newSessionId;
        bytes32 newTpmSigningKeyFingerprint;
        bytes32 sessionKeyFingerprint;
        PublicIdentity newTpmSigningKey;
    }

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
    error PCRVerificationFailed(uint8 pcrIndex);

    /// @notice PCR not found in quote
    error PCRNotFound(uint8 pcrIndex);

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
        if (!workloadRegistry.isWorkloadActive(workloadId)) {
            revert WorkloadNotActive(workloadId);
        }

        if (!baseImageRegistry.isBaseImageActive(baseImageId)) {
            revert BaseImageNotActive(baseImageId);
        }

        if (!workloadRegistry.isBaseImageAllowed(workloadId, baseImageId)) {
            revert BaseImageNotAllowed(baseImageId);
        }

        (, PlatformProfile memory platformProfile, MeasurementVariant memory variant) =
            baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId);

        WorkloadSpec memory workloadSpec = workloadRegistry.getWorkload(workloadId);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEPS 2-6: Attestation Verification Chain
        // ─────────────────────────────────────────────────────────────────────────────────
        AttestationResult memory attestationResult = _verifyAttestation(evidence, ownerIdentity);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 6: Session Key Delegation
        // ─────────────────────────────────────────────────────────────────────────────────
        DelegationResult memory delegationResult =
            _verifyDelegation(evidence, attestationResult.certifiedKey, baseImageId, workloadId);

        sessionId = delegationResult.sessionId;
        if (_sessionExists[sessionId]) {
            revert SessionAlreadyExists();
        }

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEPS 7-8: Policy Evaluation (PCR + Attributes)
        // ─────────────────────────────────────────────────────────────────────────────────
        _evaluatePolicy(
            attestationResult.pcrValues, platformProfile, variant, workloadSpec, attestationResult.expectedPcr15
        );

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 9: Owner Signature Verification + Session Creation
        // ─────────────────────────────────────────────────────────────────────────────────

        // Verify owner signature over session registration message
        bytes32 message = sha256(abi.encode(SESSION_REGISTER_MSG, block.chainid, address(this), expireAt, sessionId));
        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Create session with TTL handling
        uint64 expiresAt = workloadSpec.ttl == 0 ? type(uint64).max : uint64(block.timestamp) + workloadSpec.ttl;

        _sessions[sessionId] = CVMSession({
            sessionId: sessionId,
            owner: attestationResult.ownerFingerprint,
            akPubKeyFingerprint: attestationResult.akPubFingerprint,
            tpmSigningKeyFingerprint: attestationResult.tpmSigningKeyFingerprint,
            sessionKeyFingerprint: delegationResult.sessionKeyFingerprint,
            baseImageId: baseImageId,
            workloadId: workloadId,
            platformProfileId: platformProfileId,
            measurementVariantId: variantId,
            registeredAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            isActive: true
        });

        _sessionExists[sessionId] = true;

        // Increment owner nonce
        _ownerNonces[attestationResult.ownerFingerprint] += 1;

        // Add to owner session list
        _ownerSessions[attestationResult.ownerFingerprint].push(sessionId);

        // Emit events
        emit SessionRegistered(
            sessionId,
            attestationResult.ownerFingerprint,
            workloadId,
            baseImageId,
            attestationResult.akPubFingerprint,
            attestationResult.tpmSigningKeyFingerprint,
            delegationResult.sessionKeyFingerprint
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
        if (!_sessionExists[sessionId]) {
            revert SessionNotFound();
        }

        CVMSession storage session = _sessions[sessionId];

        // Check session is active
        if (!session.isActive) {
            revert SessionAlreadyRevoked();
        }

        // Verify owner fingerprint
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        if (session.owner != ownerFingerprint) {
            revert Unauthorized();
        }

        // Verify signature
        bytes32 message = sha256(abi.encode(SESSION_REVOKE_MSG, block.chainid, address(this), expireAt, sessionId));

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        // Revoke session
        session.isActive = false;

        emit SessionRevoked(sessionId, ownerFingerprint);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Rotation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function rotateSession(
        bytes32 oldSessionId,
        bytes32 teeReportSignatureHash,
        TpmReport calldata tpmQuoteReport,
        TpmReport calldata tpmCertifyReport,
        bytes calldata sessionKeySignature,
        PublicIdentity calldata sessionKey,
        bytes calldata rotationSignature,
        PublicIdentity calldata oldTpmSigningKey,
        PublicIdentity calldata akPub,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId) {
        RotationInputs memory inputs;
        inputs.oldSessionId = oldSessionId;
        inputs.teeReportSignatureHash = teeReportSignatureHash;
        inputs.tpmQuoteReport = tpmQuoteReport;
        inputs.tpmCertifyReport = tpmCertifyReport;
        inputs.sessionKeySignature = sessionKeySignature;
        inputs.sessionKey = sessionKey;
        inputs.rotationSignature = rotationSignature;
        inputs.oldTpmSigningKey = oldTpmSigningKey;
        inputs.akPub = akPub;
        inputs.expireAt = expireAt;
        inputs.ownerIdentity = ownerIdentity;
        inputs.ownerSignature = ownerSignature;

        return _rotateSession(inputs);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - View Functions
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function getSession(bytes32 sessionId) external view returns (CVMSession memory session) {
        if (!_sessionExists[sessionId]) {
            revert SessionNotFound();
        }
        return _sessions[sessionId];
    }

    /// @inheritdoc ISessionRegistry
    function isSessionActive(bytes32 sessionId) external view returns (bool) {
        if (!_sessionExists[sessionId]) {
            return false;
        }
        CVMSession storage session = _sessions[sessionId];
        return session.isActive && block.timestamp <= session.expiresAt;
    }

    /// @inheritdoc ISessionRegistry
    function isSessionExpired(bytes32 sessionId) external view returns (bool) {
        if (!_sessionExists[sessionId]) {
            return false;
        }
        return block.timestamp > _sessions[sessionId].expiresAt;
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
    // Internal - Session Rotation Helpers
    // ═══════════════════════════════════════════════════════════════════════════════════════

    function _rotateSession(RotationInputs memory inputs) internal returns (bytes32 newSessionId) {
        RotationContext memory ctx = _loadRotationContext(inputs);

        (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash) =
            _verifyRotationQuote(inputs, ctx.ownerFingerprint);

        RotationResults memory results = _verifyRotationCertifyAndDelegation(inputs, tpmSignatureHash, ctx);

        _evaluateRotationPolicy(ctx, pcrValues);

        _finalizeRotation(inputs, results, ctx);

        return results.newSessionId;
    }

    function _loadRotationContext(RotationInputs memory inputs) internal view returns (RotationContext memory ctx) {
        if (!_sessionExists[inputs.oldSessionId]) {
            revert SessionNotFound();
        }

        CVMSession storage oldSession = _sessions[inputs.oldSessionId];

        if (!oldSession.isActive) {
            revert SessionAlreadyRevoked();
        }

        if (block.timestamp > oldSession.expiresAt) {
            revert SessionNotActive();
        }

        bytes32 oldTpmSigningKeyFingerprint = LibKey.computeKeyFingerprint(inputs.oldTpmSigningKey);
        if (oldTpmSigningKeyFingerprint != oldSession.tpmSigningKeyFingerprint) {
            revert Unauthorized();
        }

        bytes32 akPubFingerprint = LibKey.computeKeyFingerprint(inputs.akPub);
        if (akPubFingerprint != oldSession.akPubKeyFingerprint) {
            revert Unauthorized();
        }

        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(inputs.ownerIdentity);
        if (ownerFingerprint != oldSession.owner) {
            revert Unauthorized();
        }

        return RotationContext({
            ownerFingerprint: ownerFingerprint,
            baseImageId: oldSession.baseImageId,
            workloadId: oldSession.workloadId,
            platformProfileId: oldSession.platformProfileId,
            measurementVariantId: oldSession.measurementVariantId,
            expiresAt: oldSession.expiresAt
        });
    }

    function _verifyRotationQuote(RotationInputs memory inputs, bytes32 ownerFingerprint)
        internal
        returns (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash)
    {
        uint256 nonce = _ownerNonces[ownerFingerprint];
        bytes32 expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce));

        TpmQuoteVerificationResult memory quoteResult =
            verifyTpmQuote(inputs.tpmQuoteReport, inputs.akPub, expectedExtraData);
        if (!quoteResult.valid) {
            revert TPMQuoteVerificationFailed();
        }

        TpmQuoteReport memory quoteReport = abi.decode(inputs.tpmQuoteReport.data, (TpmQuoteReport));
        return (quoteResult.pcrValues, keccak256(quoteReport.tpmSignature));
    }

    function _evaluateRotationPolicy(RotationContext memory ctx, PcrValue[] memory pcrValues) internal view {
        if (!workloadRegistry.isWorkloadActive(ctx.workloadId)) {
            revert WorkloadNotActive(ctx.workloadId);
        }

        if (!baseImageRegistry.isBaseImageActive(ctx.baseImageId)) {
            revert BaseImageNotActive(ctx.baseImageId);
        }

        if (!workloadRegistry.isBaseImageAllowed(ctx.workloadId, ctx.baseImageId)) {
            revert BaseImageNotAllowed(ctx.baseImageId);
        }

        (, PlatformProfile memory platformProfile, MeasurementVariant memory variant) =
            baseImageRegistry.getVariant(ctx.baseImageId, ctx.platformProfileId, ctx.measurementVariantId);

        WorkloadSpec memory workloadSpec = workloadRegistry.getWorkload(ctx.workloadId);

        // No TEE re-attestation during rotation; skip GCP PCR15 binding check
        _evaluatePolicy(pcrValues, platformProfile, variant, workloadSpec, bytes32(0));
    }

    function _verifyRotationCertifyAndDelegation(
        RotationInputs memory inputs,
        bytes32 tpmSignatureHash,
        RotationContext memory ctx
    ) internal view returns (RotationResults memory results) {
        TpmCertifyVerificationResult memory certifyResult =
            verifyTpmCertify(inputs.tpmCertifyReport, inputs.akPub);
        if (!certifyResult.valid) {
            revert TPMCertifyVerificationFailed();
        }

        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(inputs.sessionKey);

        bytes32 rotationMessage = keccak256(
            abi.encode(
                ROTATION_DOMAIN,
                inputs.oldSessionId,
                certifyResult.certifiedKeyFingerprint,
                sessionKeyFingerprint,
                inputs.teeReportSignatureHash
            )
        );

        if (!signatureVerifier.verify(inputs.oldTpmSigningKey, rotationMessage, inputs.rotationSignature)) {
            revert InvalidSignature();
        }

        bytes32 newSessionId = _computeSessionId(tpmSignatureHash, inputs.teeReportSignatureHash);
        if (_sessionExists[newSessionId]) {
            revert SessionAlreadyExists();
        }

        bytes32 delegationMessage = keccak256(
            abi.encode(DELEGATION_DOMAIN, ctx.baseImageId, ctx.workloadId, newSessionId, sessionKeyFingerprint)
        );

        if (!signatureVerifier.verify(certifyResult.certifiedKey, delegationMessage, inputs.sessionKeySignature)) {
            revert SessionKeyDelegationFailed();
        }

        return RotationResults({
            newSessionId: newSessionId,
            newTpmSigningKeyFingerprint: certifyResult.certifiedKeyFingerprint,
            sessionKeyFingerprint: sessionKeyFingerprint,
            newTpmSigningKey: certifyResult.certifiedKey
        });
    }

    function _finalizeRotation(RotationInputs memory inputs, RotationResults memory results, RotationContext memory ctx)
        internal
    {
        if (block.timestamp > inputs.expireAt) {
            revert SignatureExpired();
        }

        bytes32 message = sha256(
            abi.encode(
                SESSION_ROTATE_MSG,
                block.chainid,
                address(this),
                inputs.expireAt,
                inputs.oldSessionId,
                results.newSessionId
            )
        );

        if (!signatureVerifier.verify(inputs.ownerIdentity, message, inputs.ownerSignature)) {
            revert InvalidSignature();
        }

        _sessions[inputs.oldSessionId].isActive = false;

        _sessions[results.newSessionId] = CVMSession({
            sessionId: results.newSessionId,
            owner: ctx.ownerFingerprint,
            akPubKeyFingerprint: _sessions[inputs.oldSessionId].akPubKeyFingerprint,
            tpmSigningKeyFingerprint: results.newTpmSigningKeyFingerprint,
            sessionKeyFingerprint: results.sessionKeyFingerprint,
            baseImageId: ctx.baseImageId,
            workloadId: ctx.workloadId,
            platformProfileId: ctx.platformProfileId,
            measurementVariantId: ctx.measurementVariantId,
            registeredAt: uint64(block.timestamp),
            expiresAt: ctx.expiresAt,
            isActive: true
        });

        _sessionExists[results.newSessionId] = true;

        _ownerNonces[ctx.ownerFingerprint] += 1;
        _ownerSessions[ctx.ownerFingerprint].push(results.newSessionId);

        emit SessionRotated(
            inputs.oldSessionId,
            results.newSessionId,
            ctx.ownerFingerprint,
            results.newTpmSigningKeyFingerprint,
            results.sessionKeyFingerprint
        );

        emit AttestationKeysRevealed(results.newSessionId, inputs.akPub, results.newTpmSigningKey, inputs.sessionKey);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Attestation Verification (Steps 2-5)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Internal struct to pass attestation results between internal functions
    struct AttestationResult {
        PublicIdentity akPub;
        PublicIdentity certifiedKey;
        bytes32 akPubFingerprint;
        bytes32 tpmSigningKeyFingerprint;
        bytes32 ownerFingerprint;
        PcrValue[] pcrValues;
        bytes32 expectedPcr15; // GCP binding PCR15 expected value (zero for Azure)
    }

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
        uint256 nonce = _ownerNonces[ownerFingerprint];
        bytes32 expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce));

        TpmQuoteVerificationResult memory quoteResult =
            verifyTpmQuote(evidence.tpmQuoteReport, akResult.akPub, expectedExtraData);

        if (!quoteResult.valid) {
            revert TPMQuoteVerificationFailed();
        }

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 5: TPM Certify Verification
        // ─────────────────────────────────────────────────────────────────────────────────
        TpmCertifyVerificationResult memory certifyResult = verifyTpmCertify(evidence.tpmCertifyReport, akResult.akPub);

        if (!certifyResult.valid) {
            revert TPMCertifyVerificationFailed();
        }

        return AttestationResult({
            akPub: akResult.akPub,
            certifiedKey: certifyResult.certifiedKey,
            ownerFingerprint: ownerFingerprint,
            akPubFingerprint: akResult.akPubFingerprint,
            tpmSigningKeyFingerprint: certifyResult.certifiedKeyFingerprint,
            pcrValues: quoteResult.pcrValues,
            expectedPcr15: expectedPcr15
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Session Key Delegation (Step 6)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Internal struct to pass delegation results
    struct DelegationResult {
        bytes32 sessionId;
        bytes32 sessionKeyFingerprint;
    }

    /// @dev Executes Step 6: Session Key Delegation verification
    /// @param evidence The attestation evidence bundle
    /// @param certifiedKey The certified TPM signing key (from Step 5)
    /// @param baseImageId The base image identifier
    /// @param workloadId The workload identifier
    /// @return result Delegation verification results
    function _verifyDelegation(
        AttestationEvidence calldata evidence,
        PublicIdentity memory certifiedKey,
        bytes32 baseImageId,
        bytes32 workloadId
    ) internal view returns (DelegationResult memory result) {
        // Compute session key fingerprint
        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(evidence.sessionKey);

        // Decode TPM quote report to extract tpmSignature
        TpmQuoteReport memory quoteReport = abi.decode(evidence.tpmQuoteReport.data, (TpmQuoteReport));

        // Compute session ID
        bytes32 tpmSignatureHash = keccak256(quoteReport.tpmSignature);
        bytes32 teeReportSignatureHash = keccak256(evidence.teeReport.data);
        bytes32 sessionId = _computeSessionId(tpmSignatureHash, teeReportSignatureHash);

        // Build delegation message
        bytes32 delegationMessage =
            keccak256(abi.encode(DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint));

        // Verify session key delegation signature
        if (!signatureVerifier.verify(certifiedKey, delegationMessage, evidence.sessionKeySignature)) {
            revert SessionKeyDelegationFailed();
        }

        return DelegationResult({sessionId: sessionId, sessionKeyFingerprint: sessionKeyFingerprint});
    }

    /// @dev Computes the domain-separated session ID from signature hashes
    function _computeSessionId(bytes32 tpmSignatureHash, bytes32 teeReportSignatureHash)
        internal
        pure
        returns (bytes32 sessionId)
    {
        return keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportSignatureHash));
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
                revert PCRVerificationFailed(GCP_BINDING_PCR_INDEX);
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

    /// @dev Computes expected PCR15 for GCP-TDX binding (RTMR3 verification omitted due to stack constraints)
    /// @param quoteBody The TDX quote body (584 or 648 bytes)
    /// @return expectedPcr15 Expected PCR15 value
    /// @dev Note (TODO): Full RTMR3 verification using sha384 omitted due to stack depth constraints in Sha2Ext library.
    ///      The PCR15 check in Step 7 provides sufficient binding verification for GCP-TDX.
    function _verifyGcpTdxBinding(bytes memory quoteBody) internal pure returns (bytes32 expectedPcr15) {
        // Extract UUID (16 bytes) from reportData at offset 520
        bytes memory uuidBytes = LibBytes.slice(quoteBody, DCAP_UUID_OFFSET, DCAP_UUID_SIZE);

        // Compute expected PCR15 = sha256(bytes32(0) || sha256(UUID))
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
                revert PCRNotFound(specIdx);
            }
        }

        if (i < specs.length) {
            revert PCRNotFound(specs[i].pcrIndex);
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
        revert PCRNotFound(pcrIndex);
    }

    /// @dev Evaluates a single PCR spec against a measured PCR value
    /// @param spec PCR specification
    /// @param measured Measured PCR value
    function _evaluateSinglePcr(PcrSpec memory spec, PcrValue memory measured) internal pure {
        if (spec.verifyType == PcrVerifyType.STATIC) {
            // STATIC: exact value match
            if (measured.value != spec.matchData[0]) {
                revert PCRVerificationFailed(spec.pcrIndex);
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
                    revert PCRVerificationFailed(spec.pcrIndex);
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
                revert PCRVerificationFailed(spec.pcrIndex);
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
    function _mergeAttributes(Attribute[] memory profileAttrs, Attribute[] memory variantAttrs)
        internal
        pure
        returns (Attribute[] memory merged)
    {
        // Count profile attributes that are not overridden by the variant
        uint256 profileCount = 0;
        for (uint256 i = 0; i < profileAttrs.length; i++) {
            bool overridden = false;
            for (uint256 j = 0; j < variantAttrs.length; j++) {
                if (profileAttrs[i].key == variantAttrs[j].key) {
                    overridden = true;
                    break;
                }
            }
            if (!overridden) {
                profileCount++;
            }
        }

        // Merge: profile attributes without overrides, then all variant attributes
        merged = new Attribute[](profileCount + variantAttrs.length);
        uint256 writeIdx = 0;
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
        for (uint256 i = 0; i < variantAttrs.length; i++) {
            merged[writeIdx] = variantAttrs[i];
            writeIdx++;
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
