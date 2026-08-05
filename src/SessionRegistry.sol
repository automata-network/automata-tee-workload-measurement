// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

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
import {TpmCertifyVerificationResult, TpmQuoteVerificationResult, TpmVerifier} from "./bases/TpmVerifier.sol";
import {
    CVMSession,
    MeasurementVariant,
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    PlatformProfile,
    PublicIdentity,
    ResolvedPcrPolicy,
    TpmVerificationRequest,
    WorkloadSpec
} from "./types/Common.sol";
import {
    AkPubCollateralType,
    AttestationEvidence,
    SessionKeyRotationEvidence,
    SessionRenewalAuthorization,
    TEEType,
    TeeVerificationResult
} from "./types/Evidence.sol";
import {
    DELEGATION_DOMAIN,
    SESSION_DOMAIN,
    SESSION_NONCE_DOMAIN,
    SESSION_RECOVER_MSG,
    SESSION_REGISTER_MSG,
    SESSION_RENEW_DOMAIN,
    SESSION_RENEW_MSG,
    SESSION_REVOKE_MSG,
    SESSION_ROTATE_KEY_DOMAIN,
    SESSION_ROTATE_KEY_MSG
} from "./types/Constants.sol";
import {LibBytes} from "./lib/LibBytes.sol";
import {Bytes48} from "./lib/LibBytes.sol";
import {LibKey} from "./lib/LibKey.sol";
import {PcrComparison} from "./lib/PcrComparison.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract SessionRegistry is ISessionRegistry, OwnableUpgradeable, UUPSUpgradeable {
    uint64 private constant DEFAULT_CVM_TTL = 30 days;
    uint64 internal constant INITIAL_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS = 1 hours;
    uint64 internal constant INITIAL_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS = 5 minutes;

    uint256 private constant DCAP_REPORT_DATA_OFFSET = 520;
    uint256 private constant SNP_REPORT_DATA_OFFSET = 0x50;
    uint256 private constant SNP_REPORT_ID_OFFSET = 0x140;
    uint8 private constant PROVIDER_BINDING_PCR_INDEX = 15;

    ITeeVerifier public immutable teeVerifier;
    TpmVerifier public immutable tpmVerifier;
    ISignatureVerifier public immutable signatureVerifier;
    IAkCollateralVerifier public immutable akCollateralVerifier;
    IBaseImageRegistry public immutable baseImageRegistry;
    IWorkloadRegistry public immutable workloadRegistry;
    IAmdSnpSecurityPolicyRegistry public immutable amdSnpSecurityPolicyRegistry;

    mapping(bytes32 sessionId => CVMSessionStorage session) private _sessions;
    mapping(bytes32 ownerFingerprint => uint256 nonce) private _ownerNonces;
    mapping(bytes32 sessionKeyFingerprint => bytes32 sessionId) private _sessionFingerprintsToIds;
    mapping(bytes32 rootCertHash => bool trusted) public trustedAwsNitroRootCertHashes;

    uint64 public awsDocumentMaximumAgeSeconds;
    uint64 public awsDocumentAllowedFutureClockDifferenceSeconds;

    uint256[45] private __gap;

    event AwsNitroRootCertificateTrustUpdated(bytes32 indexed rootCertHash, bool trusted);
    event AwsDocumentMaximumAgeSecondsUpdated(uint64 oldMaximumAgeSeconds, uint64 newMaximumAgeSeconds);
    event AwsDocumentAllowedFutureClockDifferenceSecondsUpdated(
        uint64 oldAllowedFutureClockDifferenceSeconds, uint64 newAllowedFutureClockDifferenceSeconds
    );

    error InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint);
    error SignatureExpired(uint64 opExpiresAt, uint64 nowTs);
    error SessionAlreadyExists();
    error SessionNotFound();
    error SessionNotActive();
    error SessionAlreadyRevoked();
    error Unauthorized(bytes32 actualFingerprint, bytes32 expectedFingerprint);
    error SessionKeyDelegationFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint);
    error SessionKeyPossessionFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint);
    error SessionFingerprintInUse(bytes32 sessionKeyFingerprint, bytes32 activeSessionId);
    error WorkloadNotActive(bytes32 workloadId);
    error BaseImageNotActive(bytes32 baseImageId);
    error BaseImageNotAllowed(bytes32 baseImageId);
    error TeeVerificationFailed();
    error UnsupportedAzureTeeType(TEEType teeType);
    error AzureMaaTeeTypeMismatch(TEEType teeReportType, TEEType maaTeeType);
    error AzureTeeReportDataTooShort(uint256 actualLength, uint256 minRequired);
    error AzureTeeReportDataMismatch(bytes32 actualBindingHash, bytes32 expectedBindingHash, bytes32 actualPadding);
    error GcpSha256PolicyBankRequired(PcrBankSelection actual);
    error AwsSha384PolicyBankRequired();
    error AwsSha384BaseImagePolicyRequired();
    error AwsTeeTypeMismatch(TEEType teeReportType, TEEType collateralTeeType);
    error AwsAmdSevSnpReportHashMismatch(bytes32 teeReportBytesHash, bytes32 collateralReportHash);
    error AwsNitroRootCertificateNotTrusted(bytes32 rootCertHash);
    error AwsDocumentTimestampInFuture(uint64 documentTimestampSeconds, uint256 blockTimestamp);
    error AwsDocumentTooOld(uint64 documentTimestampSeconds, uint256 blockTimestamp);
    error ZeroAwsNitroRootCertificateHash();
    error AttestationKeyFingerprintMismatch(bytes32 measured, bytes32 expected);
    error QualifyingDataMismatch(bytes32 measured, bytes32 expected);
    error AwsPcrDigestMismatch(bytes32 quoteDigest, bytes32 nitroDigest);
    error AwsVerificationRequestCommitmentMismatch(bytes32 quoteCommitment, bytes32 nitroCommitment);

    constructor(
        ITeeVerifier teeVerifier_,
        TpmVerifier tpmVerifier_,
        ISignatureVerifier signatureVerifier_,
        IAkCollateralVerifier akCollateralVerifier_,
        IBaseImageRegistry baseImageRegistry_,
        IWorkloadRegistry workloadRegistry_,
        IAmdSnpSecurityPolicyRegistry amdSnpSecurityPolicyRegistry_
    ) {
        teeVerifier = teeVerifier_;
        tpmVerifier = tpmVerifier_;
        signatureVerifier = signatureVerifier_;
        akCollateralVerifier = akCollateralVerifier_;
        baseImageRegistry = baseImageRegistry_;
        workloadRegistry = workloadRegistry_;
        amdSnpSecurityPolicyRegistry = amdSnpSecurityPolicyRegistry_;
        _disableInitializers();
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
        awsDocumentMaximumAgeSeconds = INITIAL_AWS_DOCUMENT_MAXIMUM_AGE_SECONDS;
        awsDocumentAllowedFutureClockDifferenceSeconds = INITIAL_AWS_DOCUMENT_ALLOWED_FUTURE_CLOCK_DIFFERENCE_SECONDS;
    }

    function setAwsNitroRootCertificateTrust(bytes32 rootCertHash, bool trusted) external onlyOwner {
        if (rootCertHash == bytes32(0)) revert ZeroAwsNitroRootCertificateHash();
        trustedAwsNitroRootCertHashes[rootCertHash] = trusted;
        emit AwsNitroRootCertificateTrustUpdated(rootCertHash, trusted);
    }

    function setAwsDocumentMaximumAgeSeconds(uint64 newMaximumAgeSeconds) external onlyOwner {
        uint64 oldMaximumAgeSeconds = awsDocumentMaximumAgeSeconds;
        awsDocumentMaximumAgeSeconds = newMaximumAgeSeconds;
        emit AwsDocumentMaximumAgeSecondsUpdated(oldMaximumAgeSeconds, newMaximumAgeSeconds);
    }

    function setAwsDocumentAllowedFutureClockDifferenceSeconds(uint64 newAllowedFutureClockDifferenceSeconds)
        external
        onlyOwner
    {
        uint64 oldAllowedFutureClockDifferenceSeconds = awsDocumentAllowedFutureClockDifferenceSeconds;
        awsDocumentAllowedFutureClockDifferenceSeconds = newAllowedFutureClockDifferenceSeconds;
        emit AwsDocumentAllowedFutureClockDifferenceSecondsUpdated(
            oldAllowedFutureClockDifferenceSeconds, newAllowedFutureClockDifferenceSeconds
        );
    }

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

    function revokeSession(
        bytes32 sessionId,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        _requireNotExpired(opExpiresAt);
        CVMSessionStorage storage stored = _sessions[sessionId];
        if (!stored.exists) revert SessionNotFound();
        if (stored.isRevoked) revert SessionAlreadyRevoked();
        bytes32 ownerFingerprint = _requireFingerprint(ownerIdentity, stored.owner);
        bytes32 message = sha256(abi.encode(SESSION_REVOKE_MSG, block.chainid, address(this), opExpiresAt, sessionId));
        _requireSignature(ownerIdentity, message, ownerSignature);
        stored.isRevoked = true;
        _clearSessionFingerprint(sessionId, stored.session.sessionKeyFingerprint);
        emit SessionRevoked(sessionId, ownerFingerprint);
    }

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

        bytes32 renewalMessage = keccak256(
            abi.encode(
                SESSION_RENEW_DOMAIN,
                block.chainid,
                address(this),
                oldSessionId,
                newSessionId,
                keccak256(abi.encode(newEvidence))
            )
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

    function getSession(bytes32 sessionId) external view returns (CVMSession memory session) {
        CVMSessionStorage storage stored = _sessions[sessionId];
        if (!stored.exists) revert SessionNotFound();
        return stored.session;
    }

    function getSessionId(bytes32 sessionFingerprint) external view returns (bytes32 sessionId) {
        sessionId = _sessionFingerprintsToIds[sessionFingerprint];
        if (sessionId == bytes32(0) || !_isSessionActive(_sessions[sessionId])) return bytes32(0);
    }

    function getSessionOwner(bytes32 sessionId) external view returns (bytes32 ownerFingerprint) {
        CVMSessionStorage storage stored = _sessions[sessionId];
        if (!stored.exists) revert SessionNotFound();
        return stored.owner;
    }

    function isSessionActive(bytes32 sessionId) external view returns (bool) {
        return _isSessionActive(_sessions[sessionId]);
    }

    function isSessionExpired(bytes32 sessionId) external view returns (bool) {
        CVMSessionStorage storage stored = _sessions[sessionId];
        if (!stored.exists) revert SessionNotFound();
        return block.timestamp > stored.session.sessionExpiresAt;
    }

    function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce) {
        return _ownerNonces[ownerFingerprint];
    }

    function getPcrPolicy(
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 measurementVariantId
    ) external view returns (ResolvedPcrPolicy memory policy) {
        return _lookupPolicy(workloadId, baseImageId, platformProfileId, measurementVariantId).policy;
    }

    function verifySessionSignature(
        bytes32 sessionId,
        PublicIdentity calldata sessionKey,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool valid) {
        CVMSessionStorage storage stored = _sessions[sessionId];
        if (!_isSessionActive(stored)) return false;
        if (LibKey.computeKeyFingerprint(sessionKey) != stored.session.sessionKeyFingerprint) return false;
        return signatureVerifier.verify(sessionKey, message, signature);
    }

    struct PolicyContext {
        PlatformProfile platformProfile;
        MeasurementVariant variant;
        WorkloadSpec workloadSpec;
        ResolvedPcrPolicy policy;
    }

    struct GeneratedProviderPcrRules {
        PcrSpec256[] pcrs256;
        PcrSpec384[] pcrs384;
    }

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

    struct AttestationResult {
        PublicIdentity akPub;
        PublicIdentity certifiedKey;
        bytes32 ownerFingerprint;
        bytes32 akPubFingerprint;
        bytes32 tpmSigningKeyFingerprint;
        bytes32 teeReportBytesHash;
        bytes32 tpmSignatureHash;
    }

    struct FullSessionResult {
        AttestationResult attestation;
        bytes32 sessionId;
        bytes32 sessionKeyFingerprint;
        uint64 sessionExpiresAt;
    }

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
        PolicyContext memory policyContext =
            _lookupPolicy(workloadId, baseImageId, platformProfileId, measurementVariantId);
        result.attestation = _verifyAttestation(evidence, ownerFingerprint, policyContext);
        result.sessionId = _computeSessionId(result.attestation.tpmSignatureHash, result.attestation.teeReportBytesHash);
        if (_sessions[result.sessionId].exists) revert SessionAlreadyExists();

        result.sessionKeyFingerprint = _verifySessionKeyDelegation(
            result.attestation.certifiedKey,
            evidence.sessionKeySignature,
            evidence.sessionKey,
            baseImageId,
            workloadId,
            result.sessionId
        );
        result.sessionExpiresAt = policyContext.workloadSpec.sessionTtl == 0
            ? uint64(block.timestamp) + DEFAULT_CVM_TTL
            : uint64(block.timestamp) + policyContext.workloadSpec.sessionTtl;
    }

    function _verifyAttestation(
        AttestationEvidence calldata evidence,
        bytes32 ownerFingerprint,
        PolicyContext memory policyContext
    ) private returns (AttestationResult memory result) {
        TeeVerificationResult memory teeResult = teeVerifier.verifyTeeReport(evidence.teeReport);
        if (!teeResult.valid) revert TeeVerificationFailed();
        _verifyTeeSecurityPolicy(teeResult, policyContext);

        bytes32 expectedQualifyingData = _expectedQualifyingData(ownerFingerprint);
        bytes32 akPubFingerprint =
            akCollateralVerifier.validateAkPub(evidence.akPubCollateral.akPubCollateralType, evidence.akPub);
        AkCollateralVerificationResult memory collateralResult =
            akCollateralVerifier.verifyAkCollateral(evidence.akPubCollateral);
        if (collateralResult.akPubFingerprint != akPubFingerprint) {
            revert AttestationKeyFingerprintMismatch(collateralResult.akPubFingerprint, akPubFingerprint);
        }

        GeneratedProviderPcrRules memory providerRules = _verifyProviderEvidence(
            evidence.akPubCollateral.akPubCollateralType,
            teeResult,
            collateralResult,
            policyContext,
            expectedQualifyingData
        );
        TpmVerificationRequest memory request = _buildTpmVerificationRequest(policyContext.policy, providerRules);
        TpmQuoteVerificationResult memory quoteResult =
            tpmVerifier.verifyTpmQuote(evidence.tpmQuoteReport, evidence.akPub, expectedQualifyingData, request);
        if (evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AwsNitroTpmProof) {
            if (quoteResult.verificationRequestCommitment != collateralResult.verificationRequestCommitment) {
                revert AwsVerificationRequestCommitmentMismatch(
                    quoteResult.verificationRequestCommitment, collateralResult.verificationRequestCommitment
                );
            }
            if (quoteResult.pcrDigest != collateralResult.pcrDigest) {
                revert AwsPcrDigestMismatch(quoteResult.pcrDigest, collateralResult.pcrDigest);
            }
        }

        _advanceOwnerNonce(ownerFingerprint);
        TpmCertifyVerificationResult memory certifyResult =
            tpmVerifier.verifyTpmCertify(evidence.tpmCertifyReport, evidence.akPub);
        return AttestationResult({
            akPub: evidence.akPub,
            certifiedKey: certifyResult.certifiedKey,
            ownerFingerprint: ownerFingerprint,
            akPubFingerprint: akPubFingerprint,
            tpmSigningKeyFingerprint: certifyResult.certifiedKeyFingerprint,
            teeReportBytesHash: teeResult.teeReportBytesHash,
            tpmSignatureHash: quoteResult.tpmSignatureHash
        });
    }

    function _verifyTeeSecurityPolicy(TeeVerificationResult memory teeResult, PolicyContext memory policyContext)
        private
        view
    {
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
            policyContext.platformProfile.attributes,
            policyContext.variant.attributes,
            policyContext.workloadSpec.requirements
        );
    }

    function _verifyProviderEvidence(
        AkPubCollateralType collateralType,
        TeeVerificationResult memory teeResult,
        AkCollateralVerificationResult memory collateralResult,
        PolicyContext memory policyContext,
        bytes32 expectedQualifyingData
    ) private view returns (GeneratedProviderPcrRules memory rules) {
        rules.pcrs256 = new PcrSpec256[](0);
        rules.pcrs384 = new PcrSpec384[](0);
        if (collateralType == AkPubCollateralType.AzureMaaJwt) {
            if (collateralResult.teeType != teeResult.teeType) {
                revert AzureMaaTeeTypeMismatch(teeResult.teeType, collateralResult.teeType);
            }
            _verifyAzureBinding(teeResult, collateralResult.bindingHash);
            return rules;
        }
        if (collateralType == AkPubCollateralType.GcpCertChain) {
            if (policyContext.policy.pcrBankSelection == PcrBankSelection.Sha384) {
                revert GcpSha256PolicyBankRequired(policyContext.policy.pcrBankSelection);
            }
            bytes32 extendValue = teeVerifier.deriveGcpPcr15ExtendValue(teeResult);
            return _gcpProviderPcrRules(extendValue);
        }

        if (policyContext.policy.pcrBankSelection == PcrBankSelection.Sha256) {
            revert AwsSha384PolicyBankRequired();
        }
        if (policyContext.policy.invariantPcrs384.length + policyContext.policy.variantPcrs384.length == 0) {
            revert AwsSha384BaseImagePolicyRequired();
        }
        if (teeResult.teeType != TEEType.AmdSevSnp || collateralResult.teeType != TEEType.AmdSevSnp) {
            revert AwsTeeTypeMismatch(teeResult.teeType, collateralResult.teeType);
        }
        if (collateralResult.amdSevSnpReportHash != teeResult.teeReportBytesHash) {
            revert AwsAmdSevSnpReportHashMismatch(teeResult.teeReportBytesHash, collateralResult.amdSevSnpReportHash);
        }
        if (!trustedAwsNitroRootCertHashes[collateralResult.awsNitroRootCertHash]) {
            revert AwsNitroRootCertificateNotTrusted(collateralResult.awsNitroRootCertHash);
        }
        if (collateralResult.qualifyingData != expectedQualifyingData) {
            revert QualifyingDataMismatch(collateralResult.qualifyingData, expectedQualifyingData);
        }
        _verifyAwsDocumentFreshness(collateralResult.documentTimestampSeconds);

        bytes32 reportId = LibBytes.readBytes32(teeResult.reportData, SNP_REPORT_ID_OFFSET);
        return _awsProviderPcrRules(reportId, policyContext.policy.pcrBankSelection);
    }

    function _gcpProviderPcrRules(bytes32 extendValue) internal pure returns (GeneratedProviderPcrRules memory rules) {
        rules.pcrs256 = new PcrSpec256[](1);
        rules.pcrs256[0] = PcrSpec256({
            pcrIndex: PROVIDER_BINDING_PCR_INDEX, comparison: PcrComparison.encodeExtendFromZero256(extendValue)
        });
        rules.pcrs384 = new PcrSpec384[](0);
    }

    function _awsProviderPcrRules(bytes32 reportId, PcrBankSelection bankSelection)
        internal
        pure
        returns (GeneratedProviderPcrRules memory rules)
    {
        rules.pcrs256 = new PcrSpec256[](0);
        Bytes48 memory extendValue384 = LibBytes.toBytes48(abi.encodePacked(bytes16(0), reportId));
        rules.pcrs384 = new PcrSpec384[](1);
        rules.pcrs384[0] = PcrSpec384({
            pcrIndex: PROVIDER_BINDING_PCR_INDEX, comparison: PcrComparison.encodeExtendFromZero384(extendValue384)
        });
        if (bankSelection == PcrBankSelection.Sha256AndSha384) {
            rules.pcrs256 = new PcrSpec256[](1);
            rules.pcrs256[0] = PcrSpec256({
                pcrIndex: PROVIDER_BINDING_PCR_INDEX, comparison: PcrComparison.encodeExtendFromZero256(reportId)
            });
        }
    }

    function _rotateKey(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionKeyRotationEvidence calldata evidence,
        uint64 opExpiresAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) private returns (bytes32 newSessionId) {
        RotationContext memory context = _loadRotationContext(
            oldSessionId, evidence.oldTpmSigningKey, evidence.akPub, ownerIdentity
        );
        PolicyContext memory policyContext = _lookupPolicy(
            context.workloadId, context.baseImageId, context.platformProfileId, context.measurementVariantId
        );
        TpmVerificationRequest memory request =
            _buildTpmVerificationRequest(policyContext.policy, _emptyGeneratedProviderPcrRules());
        bytes32 expectedQualifyingData = _expectedQualifyingData(context.ownerFingerprint);
        TpmQuoteVerificationResult memory quoteResult =
            tpmVerifier.verifyTpmQuote(evidence.tpmQuoteReport, evidence.akPub, expectedQualifyingData, request);
        _advanceOwnerNonce(context.ownerFingerprint);

        TpmCertifyVerificationResult memory certifyResult =
            tpmVerifier.verifyTpmCertify(evidence.tpmCertifyReport, evidence.akPub);
        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(evidence.sessionKey);
        _verifyRotationAuthorization(
            oldSessionId,
            certifyResult.certifiedKeyFingerprint,
            sessionKeyFingerprint,
            teeReportBytesHash,
            evidence.rotationSignature,
            evidence.oldTpmSigningKey
        );

        newSessionId = _computeSessionId(quoteResult.tpmSignatureHash, teeReportBytesHash);
        if (_sessions[newSessionId].exists) revert SessionAlreadyExists();
        sessionKeyFingerprint = _verifySessionKeyDelegation(
            certifyResult.certifiedKey,
            evidence.sessionKeySignature,
            evidence.sessionKey,
            context.baseImageId,
            context.workloadId,
            newSessionId
        );
        _finalizeRotation(
            oldSessionId,
            newSessionId,
            certifyResult.certifiedKeyFingerprint,
            sessionKeyFingerprint,
            certifyResult.certifiedKey,
            context,
            opExpiresAt,
            ownerIdentity,
            ownerSignature,
            evidence.akPub,
            evidence.sessionKey
        );
    }

    function _lookupPolicy(bytes32 workloadId, bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
        private
        view
        returns (PolicyContext memory context)
    {
        if (workloadRegistry.isWorkloadRevoked(workloadId)) revert WorkloadNotActive(workloadId);
        if (baseImageRegistry.isBaseImageRevoked(baseImageId)) revert BaseImageNotActive(baseImageId);
        if (!workloadRegistry.isBaseImageAllowed(workloadId, baseImageId)) revert BaseImageNotAllowed(baseImageId);

        (, PlatformProfile memory platformProfile, MeasurementVariant memory variant) =
            baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId);
        WorkloadSpec memory workloadSpec = workloadRegistry.getWorkload(workloadId);
        ResolvedPcrPolicy memory policy = ResolvedPcrPolicy({
            workloadId: workloadId,
            baseImageId: baseImageId,
            platformProfileId: platformProfileId,
            measurementVariantId: variantId,
            pcrBankSelection: platformProfile.pcrBankSelection,
            invariantPcrs256: platformProfile.invariantPcrs256,
            variantPcrs256: variant.variantPcrs256,
            workloadPcrs256: workloadSpec.workloadPcrs256,
            invariantPcrs384: platformProfile.invariantPcrs384,
            variantPcrs384: variant.variantPcrs384,
            workloadPcrs384: workloadSpec.workloadPcrs384
        });
        return
            PolicyContext({
                platformProfile: platformProfile, variant: variant, workloadSpec: workloadSpec, policy: policy
            });
    }

    function _buildTpmVerificationRequest(
        ResolvedPcrPolicy memory policy,
        GeneratedProviderPcrRules memory providerRules
    ) internal pure returns (TpmVerificationRequest memory request) {
        request.workloadId = policy.workloadId;
        request.baseImageId = policy.baseImageId;
        request.platformProfileId = policy.platformProfileId;
        request.measurementVariantId = policy.measurementVariantId;
        request.pcrBankSelection = policy.pcrBankSelection;
        request.pcrs256 = _mergePcrRules256(policy, providerRules.pcrs256);
        request.pcrs384 = _mergePcrRules384(policy, providerRules.pcrs384);
    }

    function _mergePcrRules256(ResolvedPcrPolicy memory policy, PcrSpec256[] memory providerRules)
        internal
        pure
        returns (PcrSpec256[] memory rules)
    {
        if (policy.pcrBankSelection == PcrBankSelection.Sha384) return new PcrSpec256[](0);
        rules = new PcrSpec256[](
            policy.invariantPcrs256.length + policy.variantPcrs256.length + policy.workloadPcrs256.length
                + providerRules.length
        );
        uint256 position;
        for (uint256 i; i < policy.invariantPcrs256.length; ++i) {
            rules[position++] = policy.invariantPcrs256[i];
        }
        for (uint256 i; i < policy.variantPcrs256.length; ++i) {
            rules[position++] = policy.variantPcrs256[i];
        }
        for (uint256 i; i < policy.workloadPcrs256.length; ++i) {
            rules[position++] = policy.workloadPcrs256[i];
        }
        for (uint256 i; i < providerRules.length; ++i) {
            rules[position++] = providerRules[i];
        }
    }

    function _mergePcrRules384(ResolvedPcrPolicy memory policy, PcrSpec384[] memory providerRules)
        internal
        pure
        returns (PcrSpec384[] memory rules)
    {
        if (policy.pcrBankSelection == PcrBankSelection.Sha256) return new PcrSpec384[](0);
        rules = new PcrSpec384[](
            policy.invariantPcrs384.length + policy.variantPcrs384.length + policy.workloadPcrs384.length
                + providerRules.length
        );
        uint256 position;
        for (uint256 i; i < policy.invariantPcrs384.length; ++i) {
            rules[position++] = policy.invariantPcrs384[i];
        }
        for (uint256 i; i < policy.variantPcrs384.length; ++i) {
            rules[position++] = policy.variantPcrs384[i];
        }
        for (uint256 i; i < policy.workloadPcrs384.length; ++i) {
            rules[position++] = policy.workloadPcrs384[i];
        }
        for (uint256 i; i < providerRules.length; ++i) {
            rules[position++] = providerRules[i];
        }
    }

    function _verifyAzureBinding(TeeVerificationResult memory teeResult, bytes32 bindingHash) private pure {
        uint256 reportDataOffset;
        if (teeResult.teeType == TEEType.IntelTDX) reportDataOffset = DCAP_REPORT_DATA_OFFSET;
        else if (teeResult.teeType == TEEType.AmdSevSnp) reportDataOffset = SNP_REPORT_DATA_OFFSET;
        else revert UnsupportedAzureTeeType(teeResult.teeType);

        uint256 minRequired = reportDataOffset + 64;
        if (teeResult.reportData.length < minRequired) {
            revert AzureTeeReportDataTooShort(teeResult.reportData.length, minRequired);
        }
        bytes32 measuredBindingHash = LibBytes.readBytes32(teeResult.reportData, reportDataOffset);
        bytes32 padding = LibBytes.readBytes32(teeResult.reportData, reportDataOffset + 32);
        if (measuredBindingHash != bindingHash || padding != bytes32(0)) {
            revert AzureTeeReportDataMismatch(measuredBindingHash, bindingHash, padding);
        }
    }

    function _verifyAwsDocumentFreshness(uint64 documentTimestampSeconds) internal view {
        uint256 documentTimestamp = uint256(documentTimestampSeconds);
        uint256 currentTimestamp = block.timestamp;
        if (documentTimestamp > currentTimestamp + uint256(awsDocumentAllowedFutureClockDifferenceSeconds)) {
            revert AwsDocumentTimestampInFuture(documentTimestampSeconds, currentTimestamp);
        }
        if (currentTimestamp > documentTimestamp + uint256(awsDocumentMaximumAgeSeconds)) {
            revert AwsDocumentTooOld(documentTimestampSeconds, currentTimestamp);
        }
    }

    function _emptyGeneratedProviderPcrRules() private pure returns (GeneratedProviderPcrRules memory rules) {
        rules.pcrs256 = new PcrSpec256[](0);
        rules.pcrs384 = new PcrSpec384[](0);
    }

    function _expectedQualifyingData(bytes32 ownerFingerprint) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                SESSION_NONCE_DOMAIN, block.chainid, address(this), ownerFingerprint, _ownerNonces[ownerFingerprint]
            )
        );
    }

    function _advanceOwnerNonce(bytes32 ownerFingerprint) private {
        unchecked {
            _ownerNonces[ownerFingerprint] += 1;
        }
    }

    function _loadRotationContext(
        bytes32 oldSessionId,
        PublicIdentity calldata oldTpmSigningKey,
        PublicIdentity calldata akPub,
        PublicIdentity calldata ownerIdentity
    ) private view returns (RotationContext memory context) {
        CVMSessionStorage storage stored = _sessions[oldSessionId];
        if (!stored.exists) revert SessionNotFound();
        if (stored.isRevoked) revert SessionAlreadyRevoked();
        if (block.timestamp > stored.session.sessionExpiresAt) revert SessionNotActive();
        _requireFingerprint(oldTpmSigningKey, stored.session.tpmSigningKeyFingerprint);
        _requireFingerprint(akPub, stored.session.akPubKeyFingerprint);
        return RotationContext({
            ownerFingerprint: _requireFingerprint(ownerIdentity, stored.owner),
            baseImageId: stored.session.baseImageId,
            workloadId: stored.session.workloadId,
            platformProfileId: stored.session.platformProfileId,
            measurementVariantId: stored.session.measurementVariantId,
            sessionExpiresAt: stored.session.sessionExpiresAt
        });
    }

    function _verifySessionKeyDelegation(
        PublicIdentity memory certifiedKey,
        bytes memory sessionKeySignature,
        PublicIdentity memory sessionKey,
        bytes32 baseImageId,
        bytes32 workloadId,
        bytes32 sessionId
    ) private view returns (bytes32 sessionKeyFingerprint) {
        sessionKeyFingerprint = LibKey.computeKeyFingerprint(sessionKey);
        (bytes memory delegationSignature, bytes memory possessionSignature) =
            abi.decode(sessionKeySignature, (bytes, bytes));
        bytes32 message = keccak256(
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
        if (!signatureVerifier.verify(certifiedKey, message, delegationSignature)) {
            revert SessionKeyDelegationFailed(message, sessionKeyFingerprint);
        }
        if (!signatureVerifier.verify(sessionKey, message, possessionSignature)) {
            revert SessionKeyPossessionFailed(message, sessionKeyFingerprint);
        }
    }

    function _verifyRotationAuthorization(
        bytes32 oldSessionId,
        bytes32 certifiedKeyFingerprint,
        bytes32 sessionKeyFingerprint,
        bytes32 teeReportBytesHash,
        bytes calldata rotationSignature,
        PublicIdentity calldata oldTpmSigningKey
    ) private view {
        bytes32 message = keccak256(
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
        _requireSignature(oldTpmSigningKey, message, rotationSignature);
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

    function _finalizeRotation(
        bytes32 oldSessionId,
        bytes32 newSessionId,
        bytes32 newTpmSigningKeyFingerprint,
        bytes32 sessionKeyFingerprint,
        PublicIdentity memory newTpmSigningKey,
        RotationContext memory context,
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
        emit SessionRevoked(oldSessionId, context.ownerFingerprint);
        _createSession(
            SessionParams({
                sessionId: newSessionId,
                ownerFingerprint: context.ownerFingerprint,
                akPubKeyFingerprint: _sessions[oldSessionId].session.akPubKeyFingerprint,
                tpmSigningKeyFingerprint: newTpmSigningKeyFingerprint,
                sessionKeyFingerprint: sessionKeyFingerprint,
                baseImageId: context.baseImageId,
                workloadId: context.workloadId,
                platformProfileId: context.platformProfileId,
                measurementVariantId: context.measurementVariantId,
                sessionExpiresAt: context.sessionExpiresAt
            })
        );
        emit SessionKeyRotated(
            oldSessionId, newSessionId, context.ownerFingerprint, newTpmSigningKeyFingerprint, sessionKeyFingerprint
        );
        emit AttestationKeysRevealed(newSessionId, akPub, newTpmSigningKey, sessionKey);
    }

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

    function _computeSessionId(bytes32 tpmSignatureHash, bytes32 teeReportBytesHash) private pure returns (bytes32) {
        return keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash));
    }

    function _requireFingerprint(PublicIdentity calldata identity, bytes32 expected)
        private
        pure
        returns (bytes32 fingerprint)
    {
        fingerprint = LibKey.computeKeyFingerprint(identity);
        if (fingerprint != expected) revert Unauthorized(fingerprint, expected);
    }

    function _requireSignature(PublicIdentity calldata signer, bytes32 message, bytes calldata signature) private view {
        if (!signatureVerifier.verify(signer, message, signature)) {
            revert InvalidSignature(message, LibKey.computeKeyFingerprint(signer));
        }
    }

    function _requireNotExpired(uint64 opExpiresAt) private view {
        if (block.timestamp > opExpiresAt) revert SignatureExpired(opExpiresAt, uint64(block.timestamp));
    }

    function _isSessionActive(CVMSessionStorage storage stored) private view returns (bool) {
        if (!stored.exists || stored.isRevoked || block.timestamp > stored.session.sessionExpiresAt) return false;
        if (workloadRegistry.isWorkloadRevoked(stored.session.workloadId)) return false;
        if (baseImageRegistry.isBaseImageRevoked(stored.session.baseImageId)) return false;
        return true;
    }

    function _clearSessionFingerprint(bytes32 sessionId, bytes32 sessionKeyFingerprint) private {
        if (_sessionFingerprintsToIds[sessionKeyFingerprint] == sessionId) {
            delete _sessionFingerprintsToIds[sessionKeyFingerprint];
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
