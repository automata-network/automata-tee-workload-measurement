// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";
import {ITeeVerifier} from "./interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "./interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "./interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "./interfaces/registries/IWorkloadRegistry.sol";
import {
    IAmdSnpSecurityPolicyRegistry,
    VerifiedTeePolicyInputs
} from "./interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {ISessionRegistry, CVMSessionStorage} from "./interfaces/registries/ISessionRegistry.sol";
import {TeeVerificationResult} from "./types/Evidence.sol";
import {TpmVerifier, TpmQuoteVerificationResult, TpmCertifyVerificationResult, TpmBase} from "./bases/TpmVerifier.sol";
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
    SessionKeyRotationEvidence,
    SessionRenewalAuthorization
} from "./types/Evidence.sol";
import {
    SESSION_DOMAIN,
    DELEGATION_DOMAIN,
    SESSION_ROTATE_KEY_DOMAIN,
    SESSION_NONCE_DOMAIN,
    SESSION_REGISTER_MSG,
    SESSION_REVOKE_MSG,
    SESSION_ROTATE_KEY_MSG,
    SESSION_RENEW_DOMAIN,
    SESSION_RENEW_MSG,
    SESSION_RECOVER_MSG
} from "./types/Constants.sol";
import {LibKey} from "./lib/LibKey.sol";
import {LibBytes, Bytes48} from "./lib/LibBytes.sol";
import {Sha2Ext} from "./lib/Sha2Ext.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title SessionRegistry
/// @notice Central orchestrator for CVM session registration, attestation, and policy verification
/// @dev Inherits TPM verification capabilities from TpmVerifier and delegates AK collateral
///      verification to a separate contract to keep this implementation deployable under EIP-170.
contract SessionRegistry is ISessionRegistry, TpmVerifier, OwnableUpgradeable, UUPSUpgradeable {
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
    /// @dev Offset of report_data in an SNP attestation report
    uint256 private constant SNP_REPORT_DATA_OFFSET = 0x50;
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

    /// @notice AK collateral verifier for Azure MAA JWT and GCP cert-chain verification
    IAkCollateralVerifier public immutable akCollateralVerifier;

    /// @notice Base image registry for platform profile and variant lookups
    IBaseImageRegistry public immutable baseImageRegistry;

    /// @notice Workload registry for workload policy enforcement
    IWorkloadRegistry public immutable workloadRegistry;

    /// @notice AMD SEV-SNP registry defaults and policy evaluator.
    IAmdSnpSecurityPolicyRegistry public immutable amdSnpSecurityPolicyRegistry;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Storage - Session State
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Session data storage
    mapping(bytes32 => CVMSessionStorage) private _sessions;

    /// @dev Owner nonce for replay protection
    mapping(bytes32 => uint256) private _ownerNonces;

    /// @dev Session fingerprint to session ID mapping
    mapping(bytes32 => bytes32) private _sessionFingerprintsToIds;

    /// @dev Storage gap for future upgrades (3 existing mappings → 47-slot gap)
    uint256[47] private __gap;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Owner / TPM-signed message signature failed verification
    error InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint);

    /// @notice Signature has expired
    error SignatureExpired(uint64 opExpiresAt, uint64 nowTs);

    /// @notice Session already exists
    error SessionAlreadyExists();

    /// @notice Session not found
    error SessionNotFound();

    /// @notice Session not active
    error SessionNotActive();

    /// @notice Session already revoked
    error SessionAlreadyRevoked();

    /// @notice Fingerprint mismatch (e.g. rotation / revoke ownership check)
    error Unauthorized(bytes32 actualFingerprint, bytes32 expectedFingerprint);

    /// @notice GCP cert-chain collateral with a TEE type that has no binding rule
    error UnsupportedGcpTeeType(TEEType teeType);

    /// @notice Azure MAA collateral with a TEE type that has no binding rule
    error UnsupportedAzureTeeType(TEEType teeType);

    /// @notice Azure raw TEE report_data does not contain the MAA-signed HCL binding
    error AzureTeeReportDataMismatch(bytes32 actualBindingHash, bytes32 expectedBindingHash, bytes32 actualPadding);

    /// @notice Azure verified TEE result is too short to contain the 64-byte report_data
    error AzureTeeReportDataTooShort(uint256 actualLength, uint256 minRequired);

    /// @notice The TEE type authenticated by the Azure MAA JWT differs from the verified report.
    error AzureMaaTeeTypeMismatch(TEEType teeReportType, TEEType maaTeeType);

    /// @notice AK collateral type fell through both Azure and GCP branches during binding
    error UnsupportedAkCollateralForBinding(AkPubCollateralType collateralType);

    /// @notice GCP-TDX binding: actual RTMR3 from the TDX quote differs from the value
    ///         derived from sha384(zeros || UUID). Both values are 48 bytes (SHA-384 width).
    error GcpTdxRtmr3Mismatch(bytes actualRtmr3, bytes expectedRtmr3);

    /// @notice Session key delegation signature failed verification
    error SessionKeyDelegationFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint);

    /// @notice Session key proof-of-possession signature failed verification
    error SessionKeyPossessionFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint);

    /// @notice Another active session already owns the session key fingerprint
    error SessionFingerprintInUse(bytes32 sessionKeyFingerprint, bytes32 activeSessionId);

    /// @notice STATIC PCR measured value does not match the spec
    error PCRStaticMismatch(uint8 pcrIndex, bytes32 measured, bytes32 expected);

    /// @notice STATIC requires exactly one expected final PCR value.
    error InvalidStaticMatchDataLength(uint8 pcrIndex, uint256 actualLength);

    /// @notice DYNAMIC PCR spec rejected because the measured event log is empty
    ///         (no event-hash chain to cross-check against the PCR value)
    error PCREventLogEmpty(uint8 pcrIndex, PcrVerifyType verifyType);

    /// @notice DYNAMIC_SUBSET PCR: a required unordered landmark from matchData
    ///         is absent from the measured event log
    error PCRSubsetLandmarkMissing(uint8 pcrIndex, uint256 matchIdx, bytes32 matchHash);

    /// @notice DYNAMIC_SUBSEQUENCE PCR: not all landmarks from matchData appear in the
    ///         measured event log, in order. matchData here is a list of landmarks per
    ///         spec semantics, not the full expected log — only the count of unmatched
    ///         landmarks is exposed (see docs/cvm-registry/workload-spec.md).
    error PCRSubsequenceLandmarkMissing(uint8 pcrIndex, uint256 matchedCount, uint256 expectedCount);

    /// @notice GCP PCR15 binding: measured PCR15 differs from the value derived
    ///         from the TEE report (UUID for TDX, report_id for SNP)
    error GcpPcr15Mismatch(bytes32 measured, bytes32 expected);

    /// @notice Required PCR index from the spec is missing in the measured set
    error PCRNotFound(uint8 pcrIndex);

    /// @notice The measurement variant pins a PCR index that its platform profile already
    ///         declares invariant. Invariants always hold, so this is rejected rather than
    ///         resolved in the variant's favour. BaseImageRegistry rejects such a variant at
    ///         registration; reaching this means pre-existing storage violates the rule.
    error PcrVariantOverridesInvariant(uint8 pcrIndex);

    /// @notice Attribute not found
    error AttributeNotFound(bytes32 key);

    /// @notice Attribute value is not in the requirement's allow-list
    error AttributeValueNotAllowed(bytes32 key, bytes32 actualValue);

    /// @notice A TEE verifier returned valid=false instead of reverting.
    error TeeVerificationFailed();

    /// @notice An AK collateral verifier returned valid=false instead of reverting.
    error AkCollateralVerificationFailed();

    /// @notice The effective base-image declaration differs from the verified TEE state.
    error TeeAttributeBaseImageMismatch(bytes32 key, bytes32 declaredValue, bytes32 verifiedValue);

    /// @notice The verified TEE state is not permitted by the workload.
    error TeeAttributeValueNotAllowed(bytes32 key, bytes32 actualValue);

    /// @notice Base-image and workload PLATFORM_INFO requirements contradict each other.
    error TeeAttributePolicyConflict(bytes32 key, bytes32 baseValue, bytes32 workloadValue);

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
    /// @param signatureVerifier_ Signature verifier for owner auth
    /// @param akCollateralVerifier_ AK collateral verifier for Azure MAA JWT and GCP cert-chain verification
    /// @param baseImageRegistry_ Base image registry for platform profiles
    /// @param workloadRegistry_ Workload registry for workload policies
    /// @param amdSnpSecurityPolicyRegistry_ AMD SEV-SNP registry defaults and policy evaluator
    constructor(
        ITeeVerifier teeVerifier_,
        ITpmAttestation tpmAttestation_,
        ISignatureVerifier signatureVerifier_,
        IAkCollateralVerifier akCollateralVerifier_,
        IBaseImageRegistry baseImageRegistry_,
        IWorkloadRegistry workloadRegistry_,
        IAmdSnpSecurityPolicyRegistry amdSnpSecurityPolicyRegistry_
    ) TpmBase(tpmAttestation_) {
        teeVerifier = teeVerifier_;
        signatureVerifier = signatureVerifier_;
        akCollateralVerifier = akCollateralVerifier_;
        baseImageRegistry = baseImageRegistry_;
        workloadRegistry = workloadRegistry_;
        amdSnpSecurityPolicyRegistry = amdSnpSecurityPolicyRegistry_;
        _disableInitializers();
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
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 sessionId) {
        _requireNotExpired(opExpiresAt);
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        FullSessionResult memory result =
            _prepareFullSession(evidence, workloadId, baseImageId, platformProfileId, variantId, ownerFingerprint);
        sessionId = result.sessionId;

        bytes32 message = sha256(
            abi.encode(
                SESSION_REGISTER_MSG,
                block.chainid,
                address(this),
                opExpiresAt,
                sessionId,
                workloadId,
                baseImageId,
                platformProfileId,
                variantId,
                result.sessionKeyFingerprint
            )
        );
        _requireSignature(ownerIdentity, message, ownerSignature);
        _finalizeFullSession(result, workloadId, baseImageId, platformProfileId, variantId, evidence.sessionKey);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Revocation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function revokeSession(
        bytes32 sessionId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        // Check expiry first
        _requireNotExpired(opExpiresAt);

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
        bytes32 message = sha256(abi.encode(SESSION_REVOKE_MSG, block.chainid, address(this), opExpiresAt, sessionId));
        _requireSignature(ownerIdentity, message, ownerSignature);

        // Revoke session
        sessionStorage.isRevoked = true;
        _clearSessionFingerprint(sessionId, sessionStorage.session.sessionKeyFingerprint);

        emit SessionRevoked(sessionId, ownerFingerprint);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // External Interface - Session Rotation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ISessionRegistry
    function rotateKey(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionKeyRotationEvidence calldata rotationEvidence,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId) {
        return _rotateKey(
            oldSessionId, teeReportBytesHash, rotationEvidence, opExpiresAt, ownerIdentity, ownerSignature
        );
    }

    /// @inheritdoc ISessionRegistry
    function renewSession(
        bytes32 oldSessionId,
        AttestationEvidence calldata newEvidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        SessionRenewalAuthorization calldata renewalAuthorization,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId) {
        _requireNotExpired(opExpiresAt);
        CVMSessionStorage storage predecessor = _sessions[oldSessionId];
        if (!predecessor.exists) revert SessionNotFound();
        if (!_isSessionActive(predecessor)) revert SessionNotActive();

        bytes32 ownerFingerprint = _requireFingerprint(ownerIdentity, predecessor.owner);
        _requireFingerprint(renewalAuthorization.oldTpmSigningKey, predecessor.session.tpmSigningKeyFingerprint);

        FullSessionResult memory result = _prepareFullSession(
            newEvidence, workloadId, baseImageId, platformProfileId, measurementVariantId, ownerFingerprint
        );
        newSessionId = result.sessionId;

        bytes32 evidenceHash = keccak256(abi.encode(newEvidence));
        bytes32 renewalMessage = keccak256(
            abi.encode(SESSION_RENEW_DOMAIN, block.chainid, address(this), oldSessionId, newSessionId, evidenceHash)
        );
        _requireSignature(renewalAuthorization.oldTpmSigningKey, renewalMessage, renewalAuthorization.signature);
        _requireLifecycleOwnerSignature(
            SESSION_RENEW_MSG,
            oldSessionId,
            newSessionId,
            workloadId,
            baseImageId,
            platformProfileId,
            measurementVariantId,
            result.sessionKeyFingerprint,
            opExpiresAt,
            ownerIdentity,
            ownerSignature
        );

        predecessor.isRevoked = true;
        _clearSessionFingerprint(oldSessionId, predecessor.session.sessionKeyFingerprint);
        emit SessionRevoked(oldSessionId, ownerFingerprint);
        _finalizeFullSession(
            result, workloadId, baseImageId, platformProfileId, measurementVariantId, newEvidence.sessionKey
        );
        emit SessionRenewed(oldSessionId, newSessionId, ownerFingerprint);
    }

    /// @inheritdoc ISessionRegistry
    function recoverSession(
        bytes32 oldSessionId,
        AttestationEvidence calldata newEvidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId) {
        _requireNotExpired(opExpiresAt);
        CVMSessionStorage storage predecessor = _sessions[oldSessionId];
        if (!predecessor.exists) revert SessionNotFound();
        // A recovery consumes its predecessor by revoking it, so an already-revoked predecessor
        // cannot authorize a second one. This makes recovery single-use per predecessor without
        // a dedicated flag. It costs the caller nothing: recovery is registerSession plus
        // revokeSession, so an owner whose predecessor is already revoked has nothing left to
        // revoke and simply calls registerSession. Checked before _prepareFullSession so a
        // repeat attempt fails cheaply.
        if (predecessor.isRevoked) revert SessionAlreadyRevoked();
        bytes32 ownerFingerprint = _requireFingerprint(ownerIdentity, predecessor.owner);

        FullSessionResult memory result = _prepareFullSession(
            newEvidence, workloadId, baseImageId, platformProfileId, measurementVariantId, ownerFingerprint
        );
        newSessionId = result.sessionId;
        _requireLifecycleOwnerSignature(
            SESSION_RECOVER_MSG,
            oldSessionId,
            newSessionId,
            workloadId,
            baseImageId,
            platformProfileId,
            measurementVariantId,
            result.sessionKeyFingerprint,
            opExpiresAt,
            ownerIdentity,
            ownerSignature
        );

        predecessor.isRevoked = true;
        _clearSessionFingerprint(oldSessionId, predecessor.session.sessionKeyFingerprint);
        emit SessionRevoked(oldSessionId, ownerFingerprint);
        _finalizeFullSession(
            result, workloadId, baseImageId, platformProfileId, measurementVariantId, newEvidence.sessionKey
        );
        emit SessionRecovered(oldSessionId, newSessionId, ownerFingerprint);
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
        sessionId = _sessionFingerprintsToIds[sessionFingerprint];
        if (sessionId == bytes32(0) || !_isSessionActive(_sessions[sessionId])) {
            return bytes32(0);
        }
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
            revert SessionNotFound();
        }
        return block.timestamp > sessionStorage.session.sessionExpiresAt;
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
        uint64 sessionExpiresAt;
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

    struct FullSessionResult {
        AttestationResult attestation;
        bytes32 sessionId;
        bytes32 sessionKeyFingerprint;
        uint64 sessionExpiresAt;
    }

    /// @dev Rotation context derived from the old session
    struct RotationContext {
        bytes32 ownerFingerprint;
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 sessionExpiresAt;
    }

    function _prepareFullSession(
        AttestationEvidence calldata evidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        bytes32 ownerFingerprint
    ) private returns (FullSessionResult memory result) {
        PolicyContext memory policyCtx = _lookupPolicy(workloadId, baseImageId, platformProfileId, measurementVariantId);
        result.attestation = _verifyAttestation(
            evidence,
            ownerFingerprint,
            policyCtx.platformProfile.attributes,
            policyCtx.variant.attributes,
            policyCtx.workloadSpec.requirements
        );
        result.sessionId =
            _computeSessionId(result.attestation.tpmSignatureHash, teeVerifier.getTeeReportHash(evidence.teeReport));
        if (_sessions[result.sessionId].exists) revert SessionAlreadyExists();

        result.sessionKeyFingerprint = _verifySessionKeyDelegation(
            result.attestation.certifiedKey,
            evidence.sessionKeySignature,
            evidence.sessionKey,
            baseImageId,
            workloadId,
            result.sessionId
        );
        _evaluatePolicy(
            result.attestation.pcrValues,
            policyCtx.platformProfile,
            policyCtx.variant,
            policyCtx.workloadSpec,
            result.attestation.expectedPcr15
        );
        result.sessionExpiresAt = policyCtx.workloadSpec.sessionTtl == 0
            ? uint64(block.timestamp) + DEFAULT_CVM_TTL
            : uint64(block.timestamp) + policyCtx.workloadSpec.sessionTtl;
    }

    function _finalizeFullSession(
        FullSessionResult memory result,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        PublicIdentity calldata sessionKey
    ) private {
        _createSession(
            SessionParams({
                sessionId: result.sessionId,
                ownerFingerprint: result.attestation.ownerFingerprint,
                akPubKeyFingerprint: result.attestation.akPubFingerprint,
                tpmSigningKeyFingerprint: result.attestation.tpmSigningKeyFingerprint,
                sessionKeyFingerprint: result.sessionKeyFingerprint,
                baseImageId: baseImageId,
                workloadId: workloadId,
                platformProfileId: platformProfileId,
                measurementVariantId: measurementVariantId,
                sessionExpiresAt: result.sessionExpiresAt
            })
        );
        emit SessionRegistered(
            result.sessionId,
            result.attestation.ownerFingerprint,
            workloadId,
            baseImageId,
            result.attestation.akPubFingerprint,
            result.attestation.tpmSigningKeyFingerprint,
            result.sessionKeyFingerprint
        );
        emit AttestationKeysRevealed(
            result.sessionId, result.attestation.akPub, result.attestation.certifiedKey, sessionKey
        );
    }

    function _requireLifecycleOwnerSignature(
        bytes32 domain,
        bytes32 oldSessionId,
        bytes32 newSessionId,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId,
        bytes32 sessionKeyFingerprint,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) private view {
        bytes32 message = sha256(
            abi.encode(
                domain,
                block.chainid,
                address(this),
                opExpiresAt,
                oldSessionId,
                newSessionId,
                workloadId,
                baseImageId,
                platformProfileId,
                measurementVariantId,
                sessionKeyFingerprint
            )
        );
        _requireSignature(ownerIdentity, message, ownerSignature);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - Session Rotation Helpers
    // ═══════════════════════════════════════════════════════════════════════════════════════

    function _rotateKey(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionKeyRotationEvidence calldata evidence,
        uint64 opExpiresAt,
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
            opExpiresAt,
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

        if (block.timestamp > oldSessionStorage.session.sessionExpiresAt) {
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
            sessionExpiresAt: oldSessionStorage.session.sessionExpiresAt
        });
    }

    function _finalizeRotation(
        bytes32 oldSessionId,
        bytes32 newSessionId,
        bytes32 newTpmSigningKeyFingerprint,
        bytes32 sessionKeyFingerprint,
        PublicIdentity memory newTpmSigningKey,
        RotationContext memory ctx,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature,
        PublicIdentity calldata akPub,
        PublicIdentity calldata sessionKey
    ) private {
        _requireNotExpired(opExpiresAt);

        bytes32 message = sha256(
            abi.encode(SESSION_ROTATE_KEY_MSG, block.chainid, address(this), opExpiresAt, oldSessionId, newSessionId)
        );
        _requireSignature(ownerIdentity, message, ownerSignature);

        _sessions[oldSessionId].isRevoked = true;
        _clearSessionFingerprint(oldSessionId, _sessions[oldSessionId].session.sessionKeyFingerprint);
        emit SessionRevoked(oldSessionId, ctx.ownerFingerprint);

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
                sessionExpiresAt: ctx.sessionExpiresAt
            })
        );

        emit SessionKeyRotated(
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
    function _verifyAttestation(
        AttestationEvidence calldata evidence,
        bytes32 ownerFingerprint,
        Attribute[] memory profileAttributes,
        Attribute[] memory variantAttributes,
        AttributeRequirement[] memory requirements
    ) private returns (AttestationResult memory result) {
        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 2: TEE Report Verification (verifier reverts with rich errors on failure)
        // ─────────────────────────────────────────────────────────────────────────────────
        TeeVerificationResult memory teeResult = teeVerifier.verifyTeeReport(evidence.teeReport);
        if (!teeResult.valid) {
            revert TeeVerificationFailed();
        }
        amdSnpSecurityPolicyRegistry.verifyTeePolicy(
            VerifiedTeePolicyInputs({
                teeType: teeResult.teeType,
                enabledTeeAttributes: teeResult.enabledTeeAttributes,
                intelTdxTcbStatusBit: teeResult.intelTdxTcbStatusBit,
                amdSevSnpTcbValues: teeResult.amdSevSnpTcbValues,
                amdSevSnpPlatformInfo: teeResult.amdSevSnpPlatformInfo,
                amdSevSnpCpuid: teeResult.amdSevSnpCpuid,
                amdSevSnpReportVersion: teeResult.amdSevSnpReportVersion,
                amdSevSnpLaunchMitigationVector: teeResult.amdSevSnpLaunchMitigationVector,
                amdSevSnpCurrentMitigationVector: teeResult.amdSevSnpCurrentMitigationVector
            }),
            profileAttributes,
            variantAttributes,
            requirements
        );

        // ─────────────────────────────────────────────────────────────────────────────────
        // STEP 3: AK Collateral + TEE↔vTPM Binding (verifier reverts with rich errors)
        // ─────────────────────────────────────────────────────────────────────────────────
        AkCollateralVerificationResult memory akResult =
            akCollateralVerifier.verifyAkCollateral(evidence.akPubCollateral);
        if (!akResult.valid) {
            revert AkCollateralVerificationFailed();
        }
        if (
            evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt
                && akResult.teeType != teeResult.teeType
        ) {
            revert AzureMaaTeeTypeMismatch(teeResult.teeType, akResult.teeType);
        }

        // Verify TEE-AK binding and get expected PCR15 for GCP
        bytes32 expectedPcr15 = _verifyTeeAkBinding(teeResult, evidence, akResult.bindingHash);

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
            revert Unauthorized(fingerprint, expected);
        }
    }

    /// @dev Verifies signature
    function _requireSignature(PublicIdentity calldata signer, bytes32 message, bytes calldata signature) private view {
        if (!signatureVerifier.verify(signer, message, signature)) {
            revert InvalidSignature(message, LibKey.computeKeyFingerprint(signer));
        }
    }

    /// @dev Verifies signature expiry
    function _requireNotExpired(uint64 opExpiresAt) private view {
        if (block.timestamp > opExpiresAt) {
            revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
        }
    }

    /// @dev Checks if a session exists and is active.
    /// @dev Cascades through the underlying workload + baseimage revocation flags: revoking either
    ///      flips every dependent session inactive on the next read (fail-closed). Without this,
    ///      live sessions on a compromised baseimage/workload would keep producing valid signatures
    ///      until their own sessionExpiresAt or explicit per-session revoke.
    function _isSessionActive(CVMSessionStorage storage sessionStorage) private view returns (bool) {
        if (!sessionStorage.exists || sessionStorage.isRevoked) return false;
        if (block.timestamp > sessionStorage.session.sessionExpiresAt) return false;
        if (workloadRegistry.isWorkloadRevoked(sessionStorage.session.workloadId)) return false;
        if (baseImageRegistry.isBaseImageRevoked(sessionStorage.session.baseImageId)) return false;
        return true;
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
        bytes32 expectedExtraData =
            keccak256(abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(this), ownerFingerprint, nonce));

        // verifyTpmQuote reverts with rich TpmVerifier errors on failure; valid is always true here.
        TpmQuoteVerificationResult memory quoteResult =
            verifyTpmQuote(tpmQuoteReport, akPub, abi.encodePacked(expectedExtraData));

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
        // verifyTpmCertify reverts with rich TpmVerifier errors on failure; valid is always true here.
        TpmCertifyVerificationResult memory certifyResult = verifyTpmCertify(tpmCertifyReport, akPub);

        return (certifyResult.certifiedKey, certifyResult.certifiedKeyFingerprint);
    }

    /// @dev Verifies session key delegation signature
    /// @param certifiedKey The certified TPM signing key
    /// @param sessionKeySignature abi.encode(TPM delegation signature, session-key proof-of-possession signature)
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
        (bytes memory tpmDelegationSignature, bytes memory sessionKeyPossessionSignature) =
            abi.decode(sessionKeySignature, (bytes, bytes));

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

        if (!signatureVerifier.verify(certifiedKey, delegationMessage, tpmDelegationSignature)) {
            revert SessionKeyDelegationFailed(delegationMessage, sessionKeyFingerprint);
        }
        if (!signatureVerifier.verify(sessionKey, delegationMessage, sessionKeyPossessionSignature)) {
            revert SessionKeyPossessionFailed(delegationMessage, sessionKeyFingerprint);
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
                SESSION_ROTATE_KEY_DOMAIN,
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
        bytes32 mappedSessionId = _sessionFingerprintsToIds[params.sessionKeyFingerprint];
        if (mappedSessionId != bytes32(0) && _isSessionActive(_sessions[mappedSessionId])) {
            revert SessionFingerprintInUse(params.sessionKeyFingerprint, mappedSessionId);
        }

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
                sessionExpiresAt: params.sessionExpiresAt
            })
        });

        _sessionFingerprintsToIds[params.sessionKeyFingerprint] = params.sessionId;
    }

    /// @dev Clears the reverse lookup only when it still points at the session being revoked.
    function _clearSessionFingerprint(bytes32 sessionId, bytes32 sessionKeyFingerprint) private {
        if (_sessionFingerprintsToIds[sessionKeyFingerprint] == sessionId) {
            delete _sessionFingerprintsToIds[sessionKeyFingerprint];
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal - PCR Policy Evaluation (Step 7)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Executes Step 7: platform, variant, workload, and GCP binding PCR evaluation
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
                revert GcpPcr15Mismatch(measuredPcr15.value, expectedPcr15);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Helpers - TEE-AK Binding
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Verifies TEE-AK binding based on cloud provider and TEE type
    /// @param teeResult TEE verification result (contains reportData)
    /// @param evidence Attestation evidence bundle
    /// @param bindingHash MAA-signed sha256(hclVarData) for Azure; zero for GCP
    /// @return expectedPcr15 Expected PCR15 value for GCP binding (zero for Azure)
    function _verifyTeeAkBinding(
        TeeVerificationResult memory teeResult,
        AttestationEvidence calldata evidence,
        bytes32 bindingHash
    ) private pure returns (bytes32 expectedPcr15) {
        if (evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt) {
            uint256 reportDataOffset;
            if (teeResult.teeType == TEEType.IntelTDX) {
                reportDataOffset = DCAP_REPORT_DATA_OFFSET;
            } else if (teeResult.teeType == TEEType.AmdSevSnp) {
                reportDataOffset = SNP_REPORT_DATA_OFFSET;
            } else {
                revert UnsupportedAzureTeeType(teeResult.teeType);
            }
            uint256 minRequired = reportDataOffset + 64;
            if (teeResult.reportData.length < minRequired) {
                revert AzureTeeReportDataTooShort(teeResult.reportData.length, minRequired);
            }
            bytes32 actualBindingHash = LibBytes.readBytes32(teeResult.reportData, reportDataOffset);
            bytes32 actualPadding = LibBytes.readBytes32(teeResult.reportData, reportDataOffset + 32);
            if (actualBindingHash != bindingHash || actualPadding != bytes32(0)) {
                revert AzureTeeReportDataMismatch(actualBindingHash, bindingHash, actualPadding);
            }
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
                revert UnsupportedGcpTeeType(teeResult.teeType);
            }
        } else {
            revert UnsupportedAkCollateralForBinding(evidence.akPubCollateral.akPubCollateralType);
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
            revert GcpTdxRtmr3Mismatch(actualRtmr3.toBytes(), expectedRtmr3.toBytes());
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

    /// @dev Unions platform invariants with the variant's PCR specs. A profile invariant always
    ///      holds: a variant may only pin PCR indices the profile leaves unpinned, never restate
    ///      or relax one. BaseImageRegistry rejects an overlapping variant at registration; this
    ///      check re-enforces the invariant at evaluation time so no storage state — including
    ///      anything written by an earlier implementation — can silently drop a profile invariant.
    /// @param invariants Platform profile invariants
    /// @param overrides Variant PCR specs (must not collide with `invariants`)
    /// @return merged Effective PCR specifications, sorted ascending by pcrIndex
    function _mergePcrSpecs(PcrSpec[] memory invariants, PcrSpec[] memory overrides)
        private
        pure
        returns (PcrSpec[] memory merged)
    {
        // Max PCR indices are 0..23, so allocate once and compact later
        merged = new PcrSpec[](24);

        uint256 overrideMask = 0;
        uint256 presentMask = 0;

        // Place the variant specs while building overrideMask
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

        // Insert every invariant. An invariant is non-negotiable, so a variant spec at the
        // same index is a conflict rather than an override — fail closed instead of dropping
        // the stricter platform-level spec.
        uint256 invariantsLen = invariants.length;
        for (uint256 i = 0; i < invariantsLen;) {
            uint256 idx = uint256(invariants[i].pcrIndex);
            uint256 bit = (uint256(1) << idx);
            if ((overrideMask & bit) != 0) {
                revert PcrVariantOverridesInvariant(uint8(idx));
            }
            merged[idx] = invariants[i];
            presentMask |= bit;
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
                revert PCRNotFound(specIdx);
            }
        }

        if (i < specsLen) {
            revert PCRNotFound(specs[i].pcrIndex);
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
        revert PCRNotFound(pcrIndex);
    }

    /// @dev Evaluates a single PCR spec against a measured PCR value
    /// @param spec PCR specification
    /// @param measured Measured PCR value
    function _evaluateSinglePcr(PcrSpec memory spec, PcrValue memory measured) internal pure {
        if (spec.verifyType == PcrVerifyType.STATIC) {
            uint256 matchDataLength = spec.matchData.length;
            if (matchDataLength != 1) {
                revert InvalidStaticMatchDataLength(spec.pcrIndex, matchDataLength);
            }
            // STATIC: exact value match
            if (measured.value != spec.matchData[0]) {
                revert PCRStaticMismatch(spec.pcrIndex, measured.value, spec.matchData[0]);
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSET) {
            // DYNAMIC_SUBSET: matchData ⊆ eventLogHashes. matchData is a set of
            // required unordered landmarks; additional measured events are permitted.
            // The measured log MUST be non-empty so the TPM library cross-checks the
            // cumulative event-hash chain against the quoted PCR value.
            uint256 measuredLen = measured.eventLogHashes.length;
            if (measuredLen == 0) {
                revert PCREventLogEmpty(spec.pcrIndex, PcrVerifyType.DYNAMIC_SUBSET);
            }
            uint256 matchLen = spec.matchData.length;
            for (uint256 i = 0; i < matchLen;) {
                bool found = false;
                for (uint256 j = 0; j < measuredLen;) {
                    if (spec.matchData[i] == measured.eventLogHashes[j]) {
                        found = true;
                        break;
                    }
                    unchecked {
                        ++j;
                    }
                }
                if (!found) {
                    revert PCRSubsetLandmarkMissing(spec.pcrIndex, i, spec.matchData[i]);
                }
                unchecked {
                    ++i;
                }
            }
        } else if (spec.verifyType == PcrVerifyType.DYNAMIC_SUBSEQUENCE) {
            // DYNAMIC_SUBSEQUENCE: matchData is subsequence of eventLogHashes. Empty event log
            // is rejected for the same reason as DYNAMIC_SUBSET (no event hash chain verification).
            // The matchIdx != matchLen check below already catches this when matchData is
            // non-empty (rejected at registration), but the explicit guard documents intent.
            uint256 measuredLen = measured.eventLogHashes.length;
            if (measuredLen == 0) {
                revert PCREventLogEmpty(spec.pcrIndex, PcrVerifyType.DYNAMIC_SUBSEQUENCE);
            }
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
                // matchData is a list of landmarks, not the full expected log — only the
                // count of unmatched landmarks is exposed. Do not surface matchData[matchIdx]
                // as "the expected hash" (see workload-spec subsequence semantics).
                revert PCRSubsequenceLandmarkMissing(spec.pcrIndex, matchIdx, matchLen);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Internal Functions - UUPS
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @dev Authorizes an upgrade to a new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
