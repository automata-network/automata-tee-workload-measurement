// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";
import {ITeeVerifier} from "./interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {IBaseImageRegistry} from "./interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "./interfaces/registries/IWorkloadRegistry.sol";
import {IMaaKeyRegistry} from "./interfaces/registries/IMaaKeyRegistry.sol";
import {ISessionRegistry, CVMSessionStorage} from "./interfaces/registries/ISessionRegistry.sol";
import {TeeVerificationResult} from "./types/Evidence.sol";
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
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SessionRegistry
/// @notice Central orchestrator for CVM session registration with 9-step attestation verification
/// @dev Inherits verification capabilities from TpmVerifier and AkCollateralVerifier.
///      Coordinates with BaseImageRegistry and WorkloadRegistry to enforce platform and workload policies.
contract SessionRegistry is ISessionRegistry, TpmVerifier, AkCollateralVerifier, OwnableUpgradeable, UUPSUpgradeable {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════════════════════════════════════════

    uint64 private constant DEFAULT_CVM_TTL = 30 days;
    /// @dev Offset of RTMR3 in TDX quote body (TD10/TD15)
    uint256 private constant DCAP_RTMR3_OFFSET = 472;
    /// @dev Size of RTMR3 field (SHA-384 hash)
    uint256 private constant DCAP_RTMR3_SIZE = 48;
    /// @dev Offset of reportData UUID in TDX quote body
    uint256 private constant DCAP_REPORT_DATA_OFFSET = 520;
    /// @dev Offset of report_id in SNP attestation report
    uint256 private constant SNP_REPORT_ID_OFFSET = 0x140;
    /// @dev Size of report_id field
    uint256 private constant SNP_REPORT_ID_SIZE = 32;
    /// @dev PCR index used for GCP TEE-AK binding
    uint8 private constant GCP_BINDING_PCR_INDEX = 15;
    /// @dev Size of UUID field
    uint256 private constant GCP_UUID_SIZE = 16;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables - Registry Dependencies
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TEE verifier for TEE attestation report verification
    ITeeVerifier public immutable teeVerifier;

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

    /// @dev Session fingerprint to session ID mapping
    mapping(bytes32 => bytes32) private _sessionFingerprintsToIds;

    /// @dev Storage gap for future upgrades (4 existing mappings → 46-slot gap)
    uint256[47] private __gap;

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
    /// @param teeVerifier_ TEE verifier for TEE attestation report verification
    /// @param tpmAttestation_ TPM attestation verifier from automata-tpm-attestation
    /// @param signatureVerifier_ Signature verifier for owner auth + MAA JWT verification
    /// @param baseImageRegistry_ Base image registry for platform profiles
    /// @param workloadRegistry_ Workload registry for workload policies
    /// @param maaKeyRegistry_ MAA signing key directory used by AkCollateralVerifier for AzureMaaJwt
    constructor(
        ITeeVerifier teeVerifier_,
        ITpmAttestation tpmAttestation_,
        ISignatureVerifier signatureVerifier_,
        IBaseImageRegistry baseImageRegistry_,
        IWorkloadRegistry workloadRegistry_,
        IMaaKeyRegistry maaKeyRegistry_
    ) TpmBase(tpmAttestation_) AkCollateralVerifier(maaKeyRegistry_) {
        teeVerifier = teeVerifier_;
        signatureVerifier = signatureVerifier_;
        baseImageRegistry = baseImageRegistry_;
        workloadRegistry = workloadRegistry_;
        _disableInitializers();
    }

    /// @dev AkCollateralVerifier requires a virtual getter for the ISignatureVerifier used to
    ///      verify MAA JWT signatures (Azure path); we satisfy it by returning the same
    ///      immutable used for owner authentication, keeping a single source of truth.
    function _signatureVerifier() internal view override returns (ISignatureVerifier) {
        return signatureVerifier;
    }

    /// @notice Initializes the contract with the initial owner
    /// @param initialOwner The address that will own the contract
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
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
        _requireNotExpired(expireAt);

        // ─────────────────────────────────────────────────────────────────────────────────
        // Pre-compute owner fingerprint
        // ─────────────────────────────────────────────────────────────────────────────────
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 1: Policy Lookup
        // ─────────────────────────────────────────────────────────────────────────────────
        PolicyContext memory policyCtx = _lookupPolicy(workloadId, baseImageId, platformProfileId, variantId);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEPS 2-5: Attestation Verification Chain
        // ─────────────────────────────────────────────────────────────────────────────────
        AttestationResult memory attestationResult = _verifyAttestation(evidence, ownerFingerprint);

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 6: Session ID Computation + Session Key Delegation
        // ─────────────────────────────────────────────────────────────────────────────────
        bytes32 teeReportBytesHash = teeVerifier.getTeeReportHash(evidence.teeReport);
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
        _requireSignature(ownerIdentity, message, ownerSignature);

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
        _requireNotExpired(expireAt);

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
        bytes32 ownerFingerprint = _requireFingerprint(ownerIdentity, sessionStorage.owner);

        // Verify signature
        bytes32 message = sha256(abi.encode(SESSION_REVOKE_MSG, block.chainid, address(this), expireAt, sessionId));
        _requireSignature(ownerIdentity, message, ownerSignature);

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

    function getSessionOwner(bytes32 sessionId) external view returns (bytes32 ownerFingerprint) {
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];
        if (!sessionStorage.exists) {
            revert SessionNotFound();
        }
        return sessionStorage.owner;
    }

    /// @inheritdoc ISessionRegistry
    function isSessionActive(bytes32 sessionId) external view returns (bool) {
        return _isSessionActive(_sessions[sessionId]);
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
    function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce) {
        return _ownerNonces[ownerFingerprint];
    }

    /// @inheritdoc ISessionRegistry
    function verifySessionSignature(
        bytes32 sessionId,
        PublicIdentity calldata sessionKey,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool valid) {
        CVMSessionStorage storage sessionStorage = _sessions[sessionId];

        // Check session exists and is active
        if (!_isSessionActive(sessionStorage)) return false;

        // Verify sessionKey matches stored fingerprint
        bytes32 fingerprint = LibKey.computeKeyFingerprint(sessionKey);
        if (fingerprint != sessionStorage.session.sessionKeyFingerprint) return false;
        // Verify signature
        return signatureVerifier.verify(sessionKey, message, signature);
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
    ) private returns (bytes32 newSessionId) {
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
    ) private view returns (RotationContext memory ctx) {
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

        _requireFingerprint(oldTpmSigningKey, oldSessionStorage.session.tpmSigningKeyFingerprint);
        _requireFingerprint(akPub, oldSessionStorage.session.akPubKeyFingerprint);
        bytes32 ownerFingerprint = _requireFingerprint(ownerIdentity, oldSessionStorage.owner);

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
    ) private {
        _requireNotExpired(expireAt);

        bytes32 message =
            sha256(abi.encode(SESSION_ROTATE_MSG, block.chainid, address(this), expireAt, oldSessionId, newSessionId));
        _requireSignature(ownerIdentity, message, ownerSignature);

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
    /// @param ownerFingerprint Pre-computed owner fingerprint
    /// @return result Attestation verification results
    function _verifyAttestation(AttestationEvidence calldata evidence, bytes32 ownerFingerprint)
        private
        returns (AttestationResult memory result)
    {
        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 2: TEE Report Verification
        // ─────────────────────────────────────────────────────────────────────────────────
        TeeVerificationResult memory teeResult = teeVerifier.verifyTeeReport(evidence.teeReport);
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
        private
        pure
        returns (bytes32 sessionId)
    {
        return keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash));
    }

    /// @dev Validates a fingerprint match and returns the computed fingerprint
    function _requireFingerprint(PublicIdentity calldata identity, bytes32 expected)
        private
        pure
        returns (bytes32 fingerprint)
    {
        fingerprint = LibKey.computeKeyFingerprint(identity);
        if (fingerprint != expected) {
            revert Unauthorized();
        }
    }

    /// @dev Verifies signature
    function _requireSignature(PublicIdentity calldata signer, bytes32 message, bytes calldata signature) private view {
        if (!signatureVerifier.verify(signer, message, signature)) {
            revert InvalidSignature();
        }
    }

    /// @dev Verifies signature expiry
    function _requireNotExpired(uint64 expireAt) private view {
        if (block.timestamp > expireAt) {
            revert SignatureExpired();
        }
    }

    /// @dev Checks if a session exists and is active
    function _isSessionActive(CVMSessionStorage storage sessionStorage) private view returns (bool) {
        return sessionStorage.exists && !sessionStorage.isRevoked && block.timestamp <= sessionStorage.session.expiresAt;
    }

    /// @dev Looks up and validates policy components (workload, base image, variant)
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The measurement variant identifier
    /// @return ctx Policy context containing platform profile, variant, and workload spec
    function _lookupPolicy(bytes32 workloadId, bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        private
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
    ) private returns (PcrValue[] memory pcrValues, bytes32 tpmSignatureHash) {
        uint256 nonce = _ownerNonces[ownerFingerprint];
        bytes32 expectedExtraData = keccak256(
            abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(this), ownerFingerprint, nonce)
        );

        TpmQuoteVerificationResult memory quoteResult =
            verifyTpmQuote(tpmQuoteReport, akPub, abi.encodePacked(expectedExtraData));

        if (!quoteResult.valid) {
            revert TPMQuoteVerificationFailed();
        }

        // Increment nonce immediately after successful verification to prevent replay attacks
        unchecked {
            _ownerNonces[ownerFingerprint] = nonce + 1;
        }

        TpmQuoteReport memory quoteReport = abi.decode(tpmQuoteReport.data, (TpmQuoteReport));
        return (quoteResult.pcrValues, keccak256(quoteReport.tpmSignature));
    }

    /// @dev Verifies TPM certify and extracts the certified key
    /// @param tpmCertifyReport The TPM certify report
    /// @param akPub The attestation key public identity
    /// @return certifiedKey The certified key (TPM signing key)
    /// @return certifiedKeyFingerprint The fingerprint of the certified key
    function _verifyCertifiedKey(TpmReport memory tpmCertifyReport, PublicIdentity memory akPub)
        private
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
    ) private view returns (bytes32 sessionKeyFingerprint) {
        sessionKeyFingerprint = LibKey.computeKeyFingerprint(sessionKey);

        bytes32 delegationMessage = keccak256(
            abi.encode(
                DELEGATION_DOMAIN,
                block.chainid,
                address(this),
                baseImageId,
                workloadId,
                sessionId,
                sessionKeyFingerprint
            )
        );

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
        bytes calldata rotationSignature,
        PublicIdentity calldata oldTpmSigningKey
    ) private view {
        bytes32 rotationMessage = keccak256(
            abi.encode(
                ROTATION_DOMAIN,
                block.chainid,
                address(this),
                oldSessionId,
                certifiedKeyFingerprint,
                sessionKeyFingerprint,
                teeReportBytesHash
            )
        );

        _requireSignature(oldTpmSigningKey, rotationMessage, rotationSignature);
    }

    /// @dev Creates a new session and updates related storage
    /// @param params Session parameters for the new session
    function _createSession(SessionParams memory params) private {
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
    ) private pure {
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
    ) private view returns (bytes32 expectedPcr15) {
        if (evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt) {
            // Azure binding is anchored end-to-end inside verifyAkCollateral (§8.3.1, §14.9):
            // the MAA-signed JWT covers `tdx_report_data` / `x-ms-sevsnpvm-reportdata` which
            // commits to sha256(hclVarData), and verifyAkCollateral has already cross-checked
            // sha256(hclVarData) against that claim. The on-chain teeReport is independently
            // verified for hardware signature in Step 2; we do NOT re-check its REPORT_DATA
            // against akResult.bindingHash here. No PCR15 binding for Azure.
            return bytes32(0);
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
    function _verifyGcpTdxBinding(bytes memory quoteBody) private pure returns (bytes32 expectedPcr15) {
        // Extract UUID (16 bytes) from reportData at offset 520
        bytes memory uuidBytes = LibBytes.slice(quoteBody, DCAP_REPORT_DATA_OFFSET, GCP_UUID_SIZE);

        // ── RTMR3 Verification ──────────────────────────────────────────────
        // Extract actual RTMR3 (48 bytes) from quote body at offset 472
        Bytes48 memory actualRtmr3 = LibBytes.readBytes48(quoteBody, DCAP_RTMR3_OFFSET);

        // Expected RTMR3 = sha384( bytes48(0) || (bytes32(0) || UUID) ).
        // The extend value is the 16-byte UUID left-padded with 32 zero
        // bytes to fill the SHA-384 register width — no intermediate hash.
        Bytes48 memory expectedRtmr3 = Sha2Ext.sha384(
            abi.encodePacked(
                new bytes(48), // previous RTMR3 (reset value: 48 zero bytes)
                new bytes(32), // UUID zero-pad to 48 bytes
                uuidBytes
            )
        );

        if (!LibBytes.equal(actualRtmr3, expectedRtmr3)) {
            revert TEEAKBindingFailed();
        }

        // ── PCR15 Computation ────────────────────────────────────────────────
        // Expected PCR15 = sha256( bytes32(0) || (bytes16(0) || UUID) ).
        // Same zero-pad convention in the SHA-256 bank.
        expectedPcr15 = sha256(abi.encodePacked(bytes32(0), bytes16(0), uuidBytes));

        return expectedPcr15;
    }

    /// @dev Verifies GCP-SNP binding and computes expected PCR15
    /// @param rawReport The SNP attestation report
    /// @return expectedPcr15 Expected PCR15 value
    function _verifyGcpSnpBinding(bytes memory rawReport) private pure returns (bytes32 expectedPcr15) {
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
        private
        pure
        returns (PcrSpec[] memory merged)
    {
        // Max PCR indices are 0..23, so allocate once and compact later
        merged = new PcrSpec[](24);

        uint256 overrideMask = 0;
        uint256 presentMask = 0;

        // Apply overrides while building overrideMask
        uint256 overridesLen = overrides.length;
        for (uint256 i = 0; i < overridesLen;) {
            uint256 idx = uint256(overrides[i].pcrIndex);
            uint256 bit = (uint256(1) << idx);
            overrideMask |= bit;

            merged[idx] = overrides[i];
            presentMask |= bit;
            unchecked {
                ++i;
            }
        }

        // Insert invariants that are not overridden
        uint256 invariantsLen = invariants.length;
        for (uint256 i = 0; i < invariantsLen;) {
            uint256 idx = uint256(invariants[i].pcrIndex);
            uint256 bit = (uint256(1) << idx);
            if ((overrideMask & bit) == 0) {
                merged[idx] = invariants[i];
                presentMask |= bit;
            }
            unchecked {
                ++i;
            }
        }

        // Compact into sorted order by pcrIndex
        uint256 writeIdx = 0;
        for (uint256 idx = 0; idx < 24;) {
            if ((presentMask & (uint256(1) << idx)) != 0) {
                if (writeIdx != idx) {
                    merged[writeIdx] = merged[idx];
                }
                unchecked {
                    ++writeIdx;
                }
            }
            unchecked {
                ++idx;
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
    function _evaluatePcrSpecs(PcrSpec[] memory specs, PcrValue[] memory pcrValues) private pure {
        uint256 i = 0;
        uint256 j = 0;

        uint256 specsLen = specs.length;
        uint256 pcrLen = pcrValues.length;
        while (i < specsLen && j < pcrLen) {
            uint8 specIdx = specs[i].pcrIndex;
            uint8 measuredIdx = pcrValues[j].pcrIndex;

            if (measuredIdx == specIdx) {
                _evaluateSinglePcr(specs[i], pcrValues[j]);
                unchecked {
                    ++i;
                    ++j;
                }
            } else if (measuredIdx < specIdx) {
                // Measured PCR not required by spec, skip it
                unchecked {
                    ++j;
                }
            } else {
                // Spec PCR missing from measured set
                revert PCRNotFound();
            }
        }

        if (i < specsLen) {
            revert PCRNotFound();
        }
    }

    /// @dev Finds a PCR value by index in the measured PCR values array
    /// @param pcrValues Measured PCR values from TPM quote
    /// @param pcrIndex PCR index to find
    /// @return pcr The PCR value (reverts if not found)
    function _findPcrValue(PcrValue[] memory pcrValues, uint8 pcrIndex) private pure returns (PcrValue memory pcr) {
        uint256 pcrLen = pcrValues.length;
        for (uint256 i = 0; i < pcrLen;) {
            if (pcrValues[i].pcrIndex == pcrIndex) {
                return pcrValues[i];
            }
            unchecked {
                ++i;
            }
        }
        revert PCRNotFound();
    }

    /// @dev Evaluates a single PCR spec against a measured PCR value
    /// @param spec PCR specification
    /// @param measured Measured PCR value
    function _evaluateSinglePcr(PcrSpec memory spec, PcrValue memory measured) private pure {
        if (spec.verifyType == PcrVerifyType.STATIC) {
            // STATIC: exact value match
            if (measured.value != spec.matchData[0]) {
                revert PCRVerificationFailed();
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSET) {
            // DYNAMIC_SUBSET: eventLogHashes ⊆ matchData
            uint256 measuredLen = measured.eventLogHashes.length;
            uint256 matchLen = spec.matchData.length;
            for (uint256 i = 0; i < measuredLen;) {
                bool found = false;
                for (uint256 j = 0; j < matchLen;) {
                    if (measured.eventLogHashes[i] == spec.matchData[j]) {
                        found = true;
                        break;
                    }
                    unchecked {
                        ++j;
                    }
                }
                if (!found) {
                    revert PCRVerificationFailed();
                }
                unchecked {
                    ++i;
                }
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSEQUENCE) {
            // DYNAMIC_SUBSEQUENCE: matchData is subsequence of eventLogHashes
            uint256 measuredLen = measured.eventLogHashes.length;
            uint256 matchLen = spec.matchData.length;
            uint256 matchIdx = 0;
            for (uint256 i = 0; i < measuredLen && matchIdx < matchLen;) {
                if (measured.eventLogHashes[i] == spec.matchData[matchIdx]) {
                    unchecked {
                        ++matchIdx;
                    }
                }
                unchecked {
                    ++i;
                }
            }
            if (matchIdx != matchLen) {
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
        private
        pure
        returns (Attribute[] memory merged)
    {
        // Allocate max-size array (worst case: no overlaps)
        merged = new Attribute[](profileAttrs.length + variantAttrs.length);
        uint256 writeIdx = 0;

        // Single-pass: add profile attributes that are not overridden
        uint256 profileLen = profileAttrs.length;
        uint256 variantLen = variantAttrs.length;
        for (uint256 i = 0; i < profileLen;) {
            bool overridden = false;
            for (uint256 j = 0; j < variantLen;) {
                if (profileAttrs[i].key == variantAttrs[j].key) {
                    overridden = true;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            if (!overridden) {
                merged[writeIdx] = profileAttrs[i];
                unchecked {
                    ++writeIdx;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Add all variant attributes
        for (uint256 i = 0; i < variantLen;) {
            merged[writeIdx] = variantAttrs[i];
            unchecked {
                ++writeIdx;
                ++i;
            }
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
        private
        pure
    {
        uint256 reqLen = requirements.length;
        uint256 attrsLen = attributes.length;
        for (uint256 i = 0; i < reqLen;) {
            // Find attribute by key
            bool found = false;
            bytes32 attributeValue;

            for (uint256 j = 0; j < attrsLen;) {
                if (attributes[j].key == requirements[i].key) {
                    found = true;
                    attributeValue = attributes[j].value;
                    break;
                }
                unchecked {
                    ++j;
                }
            }

            if (!found) {
                revert AttributeNotFound(requirements[i].key);
            }

            // Check allowedValues (empty array = any value accepted)
            uint256 allowedLen = requirements[i].allowedValues.length;
            if (allowedLen > 0) {
                bool valueAllowed = false;
                for (uint256 k = 0; k < allowedLen;) {
                    if (attributeValue == requirements[i].allowedValues[k]) {
                        valueAllowed = true;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }
                if (!valueAllowed) {
                    revert AttributeValueNotAllowed(requirements[i].key);
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Functions - UUPS
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Authorizes an upgrade to a new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
