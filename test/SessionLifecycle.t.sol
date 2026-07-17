// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {MockSignatureVerifier} from "../src/mock/MockSignatureVerifier.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    CVMSession,
    MeasurementVariant,
    PcrSpec,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";
import {
    AkPubCollateral,
    AkPubCollateralType,
    AttestationEvidence,
    SessionKeyRotationEvidence,
    SessionRenewalAuthorization,
    TEEType,
    TeeReport,
    TeeVerificationResult,
    TpmCertifyReport,
    TpmQuoteReport,
    TpmReport,
    TpmReportType,
    VerificationBackendType
} from "../src/types/Evidence.sol";
import {
    ALGO_ID_ES256,
    ALGO_ID_ES256K,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    SESSION_DOMAIN,
    SESSION_NONCE_DOMAIN,
    SESSION_RECOVER_MSG,
    SESSION_RENEW_DOMAIN
} from "../src/types/Constants.sol";

contract SessionLifecycleTest is Test {
    struct PolicyIds {
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 sessionTtl;
    }

    event SessionRegistered(
        bytes32 indexed sessionId,
        bytes32 indexed owner,
        bytes32 indexed workloadId,
        bytes32 baseImageId,
        bytes32 akPubKeyFingerprint,
        bytes32 tpmSigningKeyFingerprint,
        bytes32 sessionKeyFingerprint
    );
    event AttestationKeysRevealed(
        bytes32 indexed sessionId, PublicIdentity akPub, PublicIdentity tpmSigningKey, PublicIdentity sessionKey
    );
    event SessionRevoked(bytes32 indexed sessionId, bytes32 indexed revoker);
    event SessionKeyRotated(
        bytes32 indexed oldSessionId,
        bytes32 indexed newSessionId,
        bytes32 indexed owner,
        bytes32 newTpmSigningKeyFingerprint,
        bytes32 newSessionKeyFingerprint
    );
    event SessionRenewed(bytes32 indexed oldSessionId, bytes32 indexed newSessionId, bytes32 indexed owner);
    event SessionRecovered(bytes32 indexed oldSessionId, bytes32 indexed newSessionId, bytes32 indexed owner);

    address private constant TEE_VERIFIER = address(0x1001);
    address private constant TPM_ATTESTATION = address(0x1002);
    address private constant AK_COLLATERAL_VERIFIER = address(0x1003);

    MockSignatureVerifier private signatureVerifier;
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;
    SessionRegistry private sessionRegistry;

    PublicIdentity private ownerIdentity;
    PublicIdentity private oldAk;
    PublicIdentity private oldTpmSigningKey;
    PublicIdentity private oldSessionKey;
    PolicyIds private oldPolicy;
    PolicyIds private newPolicy;

    function setUp() public {
        vm.warp(1_800_000_000);

        ownerIdentity = _identity(ALGO_ID_ES256K, 0x01);
        oldAk = _identity(ALGO_ID_ES256, 0x02);
        oldTpmSigningKey = _identity(ALGO_ID_ES256, 0x03);
        oldSessionKey = _identity(ALGO_ID_ES256K, 0x04);

        signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        sessionRegistry = new SessionRegistry(
            ITeeVerifier(TEE_VERIFIER),
            ITpmAttestation(TPM_ATTESTATION),
            ISignatureVerifier(address(signatureVerifier)),
            IAkCollateralVerifier(AK_COLLATERAL_VERIFIER),
            baseImageRegistry,
            workloadRegistry
        );

        oldPolicy = _registerPolicy("base-v1", "workload-v1", 1 days);
        newPolicy = _registerPolicy("base-v2", "workload-v2", 7 days);
    }

    function testRotateKeyInheritsPolicyAkAndAbsoluteExpiry() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("old-rotate-session");
        uint64 inheritedExpiry = uint64(block.timestamp + 12 hours);
        _seedSession(
            oldSessionId, false, inheritedExpiry, ownerFingerprint, oldAk, oldTpmSigningKey, oldSessionKey, oldPolicy
        );

        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x11);
        PublicIdentity memory newSessionKey = _identity(ALGO_ID_ES256K, 0x12);
        bytes32 teeReportBytesHash = keccak256("original-tee-report");
        SessionKeyRotationEvidence memory evidence = _rotationEvidence(0x21, oldAk, oldTpmSigningKey, newSessionKey);
        _mockQuote(ownerFingerprint, 0);
        _mockCertifiedKey(newTpmSigningKey);

        bytes32 newSessionId = _sessionId(evidence.tpmQuoteReport, teeReportBytesHash);
        bytes32 newTpmFingerprint = LibKey.computeKeyFingerprint(newTpmSigningKey);
        bytes32 newSessionFingerprint = LibKey.computeKeyFingerprint(newSessionKey);

        vm.expectEmit(true, true, false, true, address(sessionRegistry));
        emit SessionRevoked(oldSessionId, ownerFingerprint);
        vm.expectEmit(true, true, true, true, address(sessionRegistry));
        emit SessionKeyRotated(oldSessionId, newSessionId, ownerFingerprint, newTpmFingerprint, newSessionFingerprint);
        vm.expectEmit(true, false, false, true, address(sessionRegistry));
        emit AttestationKeysRevealed(newSessionId, oldAk, newTpmSigningKey, newSessionKey);

        assertEq(
            sessionRegistry.rotateKey(
                oldSessionId, teeReportBytesHash, evidence, uint64(block.timestamp + 5 minutes), ownerIdentity, hex"01"
            ),
            newSessionId
        );

        CVMSession memory successor = sessionRegistry.getSession(newSessionId);
        assertEq(successor.akPubKeyFingerprint, LibKey.computeKeyFingerprint(oldAk));
        assertEq(successor.tpmSigningKeyFingerprint, newTpmFingerprint);
        assertEq(successor.sessionKeyFingerprint, newSessionFingerprint);
        _assertPolicy(successor, oldPolicy);
        assertEq(successor.registeredAt, uint64(block.timestamp));
        assertEq(successor.sessionExpiresAt, inheritedExpiry, "rotateKey must not grant a fresh TTL");
        assertFalse(sessionRegistry.isSessionActive(oldSessionId));
        assertTrue(sessionRegistry.isSessionActive(newSessionId));
        assertEq(sessionRegistry.getNonce(ownerFingerprint), 1);
    }

    function testRotateKeyRejectsAkChange() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("old-rotate-ak-mismatch");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp + 1 days),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory differentAk = _identity(ALGO_ID_ES256, 0x13);
        SessionKeyRotationEvidence memory evidence =
            _rotationEvidence(0x22, differentAk, oldTpmSigningKey, _identity(ALGO_ID_ES256K, 0x14));

        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.Unauthorized.selector,
                LibKey.computeKeyFingerprint(differentAk),
                LibKey.computeKeyFingerprint(oldAk)
            )
        );
        sessionRegistry.rotateKey(
            oldSessionId, keccak256("tee"), evidence, uint64(block.timestamp + 5 minutes), ownerIdentity, hex"01"
        );
    }

    function testRenewSessionAllowsFreshAkAndPolicyAndGrantsFreshTtl() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("old-renew-session");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp + 2 hours),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory newAk = _identity(ALGO_ID_ES256, 0x31);
        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x32);
        PublicIdentity memory newSessionKey = _identity(ALGO_ID_ES256K, 0x33);
        AttestationEvidence memory evidence = _fullEvidence(0x34, newSessionKey);
        bytes32 teeReportHash = keccak256(evidence.teeReport.data);
        _mockFullEvidence(evidence, ownerFingerprint, 0, newAk, newTpmSigningKey, teeReportHash);

        bytes32 newSessionId = _sessionId(evidence.tpmQuoteReport, teeReportHash);
        bytes32 newAkFingerprint = LibKey.computeKeyFingerprint(newAk);
        bytes32 newTpmFingerprint = LibKey.computeKeyFingerprint(newTpmSigningKey);
        bytes32 newSessionFingerprint = LibKey.computeKeyFingerprint(newSessionKey);
        SessionRenewalAuthorization memory authorization =
            SessionRenewalAuthorization({signature: hex"02", oldTpmSigningKey: oldTpmSigningKey});

        vm.expectEmit(true, true, false, true, address(sessionRegistry));
        emit SessionRevoked(oldSessionId, ownerFingerprint);
        vm.expectEmit(true, true, true, true, address(sessionRegistry));
        emit SessionRegistered(
            newSessionId,
            ownerFingerprint,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newAkFingerprint,
            newTpmFingerprint,
            newSessionFingerprint
        );
        vm.expectEmit(true, false, false, true, address(sessionRegistry));
        emit AttestationKeysRevealed(newSessionId, newAk, newTpmSigningKey, newSessionKey);
        vm.expectEmit(true, true, true, true, address(sessionRegistry));
        emit SessionRenewed(oldSessionId, newSessionId, ownerFingerprint);

        assertEq(
            sessionRegistry.renewSession(
                oldSessionId,
                evidence,
                newPolicy.workloadId,
                newPolicy.baseImageId,
                newPolicy.platformProfileId,
                newPolicy.measurementVariantId,
                authorization,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"03"
            ),
            newSessionId
        );

        CVMSession memory successor = sessionRegistry.getSession(newSessionId);
        assertEq(successor.akPubKeyFingerprint, newAkFingerprint);
        assertEq(successor.tpmSigningKeyFingerprint, newTpmFingerprint);
        assertEq(successor.sessionKeyFingerprint, newSessionFingerprint);
        _assertPolicy(successor, newPolicy);
        assertEq(successor.sessionExpiresAt, uint64(block.timestamp) + newPolicy.sessionTtl);
        assertFalse(sessionRegistry.isSessionActive(oldSessionId));
        assertTrue(sessionRegistry.isSessionActive(newSessionId));
    }

    function testRenewSessionRejectsEvidenceSubstitution() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("old-renew-substitution");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp + 1 days),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory newAk = _identity(ALGO_ID_ES256, 0x41);
        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x42);
        AttestationEvidence memory substitutedEvidence = _fullEvidence(0x44, _identity(ALGO_ID_ES256K, 0x43));
        bytes32 teeReportHash = keccak256(substitutedEvidence.teeReport.data);
        _mockFullEvidence(substitutedEvidence, ownerFingerprint, 0, newAk, newTpmSigningKey, teeReportHash);

        bytes32 newSessionId = _sessionId(substitutedEvidence.tpmQuoteReport, teeReportHash);
        bytes32 renewalMessage = keccak256(
            abi.encode(
                SESSION_RENEW_DOMAIN,
                block.chainid,
                address(sessionRegistry),
                oldSessionId,
                newSessionId,
                keccak256(abi.encode(substitutedEvidence))
            )
        );
        bytes memory predecessorSignature = hex"a1";
        vm.mockCall(
            address(signatureVerifier),
            abi.encodeCall(ISignatureVerifier.verify, (oldTpmSigningKey, renewalMessage, predecessorSignature)),
            abi.encode(false)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.InvalidSignature.selector,
                renewalMessage,
                LibKey.computeKeyFingerprint(oldTpmSigningKey)
            )
        );
        sessionRegistry.renewSession(
            oldSessionId,
            substitutedEvidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            SessionRenewalAuthorization({signature: predecessorSignature, oldTpmSigningKey: oldTpmSigningKey}),
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"03"
        );
    }

    function testRecoverSessionRejectsMissingAndWrongOwnerPredecessors() public {
        AttestationEvidence memory evidence = _fullEvidence(0x51, _identity(ALGO_ID_ES256K, 0x52));

        vm.expectRevert(SessionRegistry.SessionNotFound.selector);
        sessionRegistry.recoverSession(
            keccak256("missing"),
            evidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );

        bytes32 oldSessionId = keccak256("wrong-owner-session");
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _seedSession(
            oldSessionId,
            true,
            uint64(block.timestamp - 1),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );
        PublicIdentity memory wrongOwner = _identity(ALGO_ID_ES256K, 0x53);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.Unauthorized.selector, LibKey.computeKeyFingerprint(wrongOwner), ownerFingerprint
            )
        );
        sessionRegistry.recoverSession(
            oldSessionId,
            evidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            wrongOwner,
            hex"01"
        );
    }

    function testRecoverSessionReplacesExpiredPredecessor() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("expired-recovery-session");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp - 1),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory newAk = _identity(ALGO_ID_ES256, 0x61);
        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x62);
        PublicIdentity memory newSessionKey = _identity(ALGO_ID_ES256K, 0x63);
        AttestationEvidence memory evidence = _fullEvidence(0x64, newSessionKey);
        bytes32 teeReportHash = keccak256(evidence.teeReport.data);
        _mockFullEvidence(evidence, ownerFingerprint, 0, newAk, newTpmSigningKey, teeReportHash);
        bytes32 newSessionId = _sessionId(evidence.tpmQuoteReport, teeReportHash);

        vm.expectEmit(true, true, false, true, address(sessionRegistry));
        emit SessionRevoked(oldSessionId, ownerFingerprint);
        vm.expectEmit(true, true, true, true, address(sessionRegistry));
        emit SessionRegistered(
            newSessionId,
            ownerFingerprint,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            LibKey.computeKeyFingerprint(newAk),
            LibKey.computeKeyFingerprint(newTpmSigningKey),
            LibKey.computeKeyFingerprint(newSessionKey)
        );
        vm.expectEmit(true, false, false, true, address(sessionRegistry));
        emit AttestationKeysRevealed(newSessionId, newAk, newTpmSigningKey, newSessionKey);
        vm.expectEmit(true, true, true, true, address(sessionRegistry));
        emit SessionRecovered(oldSessionId, newSessionId, ownerFingerprint);

        assertEq(
            sessionRegistry.recoverSession(
                oldSessionId,
                evidence,
                newPolicy.workloadId,
                newPolicy.baseImageId,
                newPolicy.platformProfileId,
                newPolicy.measurementVariantId,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"01"
            ),
            newSessionId
        );
        assertTrue(sessionRegistry.isSessionActive(newSessionId));
        assertEq(
            sessionRegistry.getSession(newSessionId).sessionExpiresAt, uint64(block.timestamp) + newPolicy.sessionTtl
        );
    }

    function testRecoverSessionDoesNotEmitDuplicateRevocationForRevokedPredecessor() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("revoked-recovery-session");
        _seedSession(
            oldSessionId,
            true,
            uint64(block.timestamp - 1),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory newAk = _identity(ALGO_ID_ES256, 0x71);
        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x72);
        AttestationEvidence memory evidence = _fullEvidence(0x74, _identity(ALGO_ID_ES256K, 0x73));
        bytes32 teeReportHash = keccak256(evidence.teeReport.data);
        _mockFullEvidence(evidence, ownerFingerprint, 0, newAk, newTpmSigningKey, teeReportHash);

        vm.recordLogs();
        bytes32 newSessionId = sessionRegistry.recoverSession(
            oldSessionId,
            evidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 revokedTopic = keccak256("SessionRevoked(bytes32,bytes32)");
        uint256 revocationCount;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(sessionRegistry) && logs[i].topics[0] == revokedTopic) {
                revocationCount++;
            }
        }
        assertEq(revocationCount, 0);
        assertTrue(sessionRegistry.isSessionActive(newSessionId));
    }

    function testOwnerNonceRollsBackWhenRecoveryAuthorizationFails() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("nonce-rollback-session");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp - 1),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            oldPolicy
        );

        PublicIdentity memory newAk = _identity(ALGO_ID_ES256, 0x81);
        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0x82);
        PublicIdentity memory newSessionKey = _identity(ALGO_ID_ES256K, 0x83);
        AttestationEvidence memory evidence = _fullEvidence(0x84, newSessionKey);
        bytes32 teeReportHash = keccak256(evidence.teeReport.data);
        _mockFullEvidence(evidence, ownerFingerprint, 0, newAk, newTpmSigningKey, teeReportHash);
        bytes32 newSessionId = _sessionId(evidence.tpmQuoteReport, teeReportHash);
        uint64 opExpiresAt = uint64(block.timestamp + 5 minutes);
        bytes32 ownerMessage = sha256(
            abi.encode(
                SESSION_RECOVER_MSG,
                block.chainid,
                address(sessionRegistry),
                opExpiresAt,
                oldSessionId,
                newSessionId,
                newPolicy.workloadId,
                newPolicy.baseImageId,
                newPolicy.platformProfileId,
                newPolicy.measurementVariantId,
                LibKey.computeKeyFingerprint(newSessionKey)
            )
        );
        bytes memory invalidOwnerSignature = hex"ff";
        vm.mockCall(
            address(signatureVerifier),
            abi.encodeCall(ISignatureVerifier.verify, (ownerIdentity, ownerMessage, invalidOwnerSignature)),
            abi.encode(false)
        );

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.InvalidSignature.selector, ownerMessage, ownerFingerprint)
        );
        sessionRegistry.recoverSession(
            oldSessionId,
            evidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            opExpiresAt,
            ownerIdentity,
            invalidOwnerSignature
        );

        assertEq(sessionRegistry.getNonce(ownerFingerprint), 0, "reverted operation must not consume owner nonce");
        assertEq(sessionRegistry.getSessionOwner(oldSessionId), ownerFingerprint);
        vm.expectRevert(SessionRegistry.SessionNotFound.selector);
        sessionRegistry.getSession(newSessionId);
    }

    function testExistingStorageLayoutRemainsReadable() public {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 sessionId = keccak256("pre-upgrade-storage-row");
        uint64 expiry = uint64(block.timestamp + 9 days);
        _seedSession(sessionId, false, expiry, ownerFingerprint, oldAk, oldTpmSigningKey, oldSessionKey, oldPolicy);

        CVMSession memory session = sessionRegistry.getSession(sessionId);
        assertEq(sessionRegistry.getSessionOwner(sessionId), ownerFingerprint);
        assertEq(session.akPubKeyFingerprint, LibKey.computeKeyFingerprint(oldAk));
        assertEq(session.tpmSigningKeyFingerprint, LibKey.computeKeyFingerprint(oldTpmSigningKey));
        assertEq(session.sessionKeyFingerprint, LibKey.computeKeyFingerprint(oldSessionKey));
        _assertPolicy(session, oldPolicy);
        assertEq(session.registeredAt, uint64(block.timestamp));
        assertEq(session.sessionExpiresAt, expiry);
        assertTrue(sessionRegistry.isSessionActive(sessionId));
    }

    function _registerPolicy(string memory baseVersion, string memory workloadVersion, uint64 ttl)
        private
        returns (PolicyIds memory ids)
    {
        BaseImageSpec memory baseImage = BaseImageSpec({name: "lifecycle-test-base", version: baseVersion, uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] =
            PlatformProfile({name: "test-platform", invariants: new PcrSpec[](0), attributes: new Attribute[](0)});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] =
            MeasurementVariant({name: "test-variant", overridePcrs: new PcrSpec[](0), attributes: new Attribute[](0)});

        ids.baseImageId = baseImageRegistry.registerBaseImage(
            baseImage, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
        ids.platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, ids.baseImageId, profiles[0].name));
        ids.measurementVariantId =
            keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, ids.platformProfileId, variants[0][0].name));

        bytes32[] memory allowedBaseImages = new bytes32[](1);
        allowedBaseImages[0] = ids.baseImageId;
        WorkloadSpec memory workload = WorkloadSpec({
            name: "lifecycle-test-workload",
            version: workloadVersion,
            sessionTtl: ttl,
            baseImageMode: AccessMode.WHITELIST,
            baseImageIds: allowedBaseImages,
            requirements: new AttributeRequirement[](0),
            pcrs: new PcrSpec[](0)
        });
        ids.workloadId =
            workloadRegistry.registerWorkload(workload, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
        ids.sessionTtl = ttl;
    }

    function _fullEvidence(uint8 marker, PublicIdentity memory sessionKey)
        private
        pure
        returns (AttestationEvidence memory evidence)
    {
        evidence.teeReport = TeeReport({
            verificationBackendType: VerificationBackendType.Solidity,
            teeType: TEEType.IntelTDX,
            data: abi.encodePacked("tee-report-", marker)
        });
        evidence.tpmQuoteReport = _quoteReport(marker);
        evidence.tpmCertifyReport = _certifyReport(marker);
        evidence.akPubCollateral =
            AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: abi.encode(marker)});
        evidence.sessionKeySignature = abi.encodePacked("delegation-", marker);
        evidence.sessionKey = sessionKey;
    }

    function _rotationEvidence(
        uint8 marker,
        PublicIdentity memory akPub,
        PublicIdentity memory predecessorTpmSigningKey,
        PublicIdentity memory sessionKey
    ) private pure returns (SessionKeyRotationEvidence memory evidence) {
        evidence.tpmQuoteReport = _quoteReport(marker);
        evidence.tpmCertifyReport = _certifyReport(marker);
        evidence.sessionKeySignature = abi.encodePacked("delegation-", marker);
        evidence.sessionKey = sessionKey;
        evidence.rotationSignature = abi.encodePacked("rotation-", marker);
        evidence.oldTpmSigningKey = predecessorTpmSigningKey;
        evidence.akPub = akPub;
    }

    function _quoteReport(uint8 marker) private pure returns (TpmReport memory) {
        PcrValue[] memory pcrValues = new PcrValue[](0);
        TpmQuoteReport memory quote = TpmQuoteReport({
            tpm2bAttest: abi.encodePacked("quote-attest-", marker),
            tpmSignature: abi.encodePacked("quote-signature-", marker),
            pcrValues: pcrValues
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmQuote,
            data: abi.encode(quote)
        });
    }

    function _certifyReport(uint8 marker) private pure returns (TpmReport memory) {
        TpmCertifyReport memory certify = TpmCertifyReport({
            tpm2bAttest: abi.encodePacked("certify-attest-", marker),
            tpmSignature: abi.encodePacked("certify-signature-", marker),
            tpmtPublic: hex"0000000000040072"
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmCertify,
            data: abi.encode(certify)
        });
    }

    function _mockFullEvidence(
        AttestationEvidence memory evidence,
        bytes32 ownerFingerprint,
        uint256 nonce,
        PublicIdentity memory akPub,
        PublicIdentity memory certifiedTpmSigningKey,
        bytes32 teeReportHash
    ) private {
        vm.mockCall(
            TEE_VERIFIER,
            abi.encodeCall(ITeeVerifier.verifyTeeReport, (evidence.teeReport)),
            abi.encode(TeeVerificationResult({valid: true, reportData: "", teeType: evidence.teeReport.teeType}))
        );
        vm.mockCall(
            TEE_VERIFIER, abi.encodeCall(ITeeVerifier.getTeeReportHash, (evidence.teeReport)), abi.encode(teeReportHash)
        );
        vm.mockCall(
            AK_COLLATERAL_VERIFIER,
            abi.encodeCall(IAkCollateralVerifier.verifyAkCollateral, (evidence.akPubCollateral)),
            abi.encode(
                AkCollateralVerificationResult({
                    valid: true,
                    akPub: akPub,
                    akPubFingerprint: LibKey.computeKeyFingerprint(akPub),
                    bindingHash: bytes32(0)
                })
            )
        );
        _mockQuote(ownerFingerprint, nonce);
        _mockCertifiedKey(certifiedTpmSigningKey);
    }

    function _mockQuote(bytes32 ownerFingerprint, uint256 nonce) private {
        bytes32 expectedExtraData = keccak256(
            abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(sessionRegistry), ownerFingerprint, nonce)
        );
        vm.mockCall(
            TPM_ATTESTATION,
            ITpmAttestation.verifyTpmQuoteWithTrustedAkPub.selector,
            abi.encode(true, abi.encodePacked(expectedExtraData))
        );
        vm.mockCall(TPM_ATTESTATION, ITpmAttestation.checkPcrMeasurements.selector, abi.encode(true, bytes("")));
    }

    function _mockCertifiedKey(PublicIdentity memory certifiedTpmSigningKey) private {
        CertPubkey memory certifiedKey = CertPubkey({algo: 0x0023, params: 0x0003, data: certifiedTpmSigningKey.key});
        vm.mockCall(
            TPM_ATTESTATION, ITpmAttestation.verifyTpmKeyCertification.selector, abi.encode(certifiedKey, bytes(""))
        );
    }

    function _seedSession(
        bytes32 sessionId,
        bool revoked,
        uint64 sessionExpiresAt,
        bytes32 ownerFingerprint,
        PublicIdentity memory akPub,
        PublicIdentity memory tpmSigningKey,
        PublicIdentity memory sessionKey,
        PolicyIds memory policy
    ) private {
        uint256 base = uint256(keccak256(abi.encode(sessionId, uint256(0))));
        uint256 flags = 1 | (revoked ? uint256(1) << 8 : 0);
        vm.store(address(sessionRegistry), bytes32(base), bytes32(flags));
        vm.store(address(sessionRegistry), bytes32(base + 1), ownerFingerprint);
        vm.store(address(sessionRegistry), bytes32(base + 2), LibKey.computeKeyFingerprint(akPub));
        vm.store(address(sessionRegistry), bytes32(base + 3), LibKey.computeKeyFingerprint(tpmSigningKey));
        vm.store(address(sessionRegistry), bytes32(base + 4), LibKey.computeKeyFingerprint(sessionKey));
        vm.store(address(sessionRegistry), bytes32(base + 5), policy.baseImageId);
        vm.store(address(sessionRegistry), bytes32(base + 6), policy.workloadId);
        vm.store(address(sessionRegistry), bytes32(base + 7), policy.platformProfileId);
        vm.store(address(sessionRegistry), bytes32(base + 8), policy.measurementVariantId);
        vm.store(
            address(sessionRegistry),
            bytes32(base + 9),
            bytes32((uint256(sessionExpiresAt) << 64) | uint64(block.timestamp))
        );
    }

    function _sessionId(TpmReport memory report, bytes32 teeReportHash) private pure returns (bytes32) {
        TpmQuoteReport memory quote = abi.decode(report.data, (TpmQuoteReport));
        return keccak256(abi.encode(SESSION_DOMAIN, keccak256(quote.tpmSignature), teeReportHash));
    }

    function _identity(uint8 typeId, uint8 marker) private pure returns (PublicIdentity memory identity) {
        bytes memory key = new bytes(65);
        key[0] = 0x04;
        key[64] = bytes1(marker);
        identity = PublicIdentity({typeId: typeId, key: key});
    }

    function _assertPolicy(CVMSession memory session, PolicyIds memory policy) private pure {
        assertEq(session.baseImageId, policy.baseImageId);
        assertEq(session.workloadId, policy.workloadId);
        assertEq(session.platformProfileId, policy.platformProfileId);
        assertEq(session.measurementVariantId, policy.measurementVariantId);
    }
}
