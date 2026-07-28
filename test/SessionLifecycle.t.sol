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
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {AmdSnpSecurityPolicyUpdate} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
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
    DELEGATION_DOMAIN,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    SESSION_DOMAIN,
    SESSION_NONCE_DOMAIN,
    SESSION_RECOVER_MSG,
    SESSION_RENEW_DOMAIN,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
    TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT,
    TDX_TCB_STATUS_OK,
    TDX_TCB_STATUS_CONFIGURATION_NEEDED,
    TEE_ATTRIBUTE_TRUE
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
    AmdSnpSecurityPolicyRegistry private amdSnpSecurityPolicyRegistry;
    SessionRegistry private sessionRegistry;

    PublicIdentity private ownerIdentity;
    PublicIdentity private oldAk;
    PublicIdentity private oldTpmSigningKey;
    PublicIdentity private oldSessionKey;
    PolicyIds private oldPolicy;
    PolicyIds private newPolicy;
    uint256 private nextTeePolicyVersion;

    function setUp() public {
        vm.warp(1_800_000_000);

        ownerIdentity = _identity(ALGO_ID_ES256K, 0x01);
        oldAk = _identity(ALGO_ID_ES256, 0x02);
        oldTpmSigningKey = _identity(ALGO_ID_ES256, 0x03);
        oldSessionKey = _identity(ALGO_ID_ES256K, 0x04);

        signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        AmdSnpSecurityPolicyRegistry amdPolicyImplementation = new AmdSnpSecurityPolicyRegistry();
        amdSnpSecurityPolicyRegistry = AmdSnpSecurityPolicyRegistry(
            address(
                new ERC1967Proxy(
                    address(amdPolicyImplementation),
                    abi.encodeCall(AmdSnpSecurityPolicyRegistry.initialize, (address(this)))
                )
            )
        );
        AmdSnpSecurityPolicyUpdate[] memory amdPolicies = new AmdSnpSecurityPolicyUpdate[](1);
        amdPolicies[0] = AmdSnpSecurityPolicyUpdate(0x191101, 0, 1, true, bytes32(0), bytes32(0), 0, 0);
        amdSnpSecurityPolicyRegistry.updatePolicies(amdPolicies, keccak256("test-policy"));
        sessionRegistry = new SessionRegistry(
            ITeeVerifier(TEE_VERIFIER),
            ITpmAttestation(TPM_ATTESTATION),
            ISignatureVerifier(address(signatureVerifier)),
            IAkCollateralVerifier(AK_COLLATERAL_VERIFIER),
            baseImageRegistry,
            workloadRegistry,
            amdSnpSecurityPolicyRegistry
        );

        oldPolicy = _registerPolicy("base-v1", "workload-v1", 1 days);
        newPolicy = _registerPolicy("base-v2", "workload-v2", 7 days);
    }

    function testIsSessionExpiredRejectsUnknownSession() public {
        vm.expectRevert(SessionRegistry.SessionNotFound.selector);
        sessionRegistry.isSessionExpired(keccak256("unknown-session"));
    }

    function testRegisterSessionRequiresSessionKeyProofOfPossession() public {
        AttestationEvidence memory evidence = _fullEvidence(0x05, _identity(ALGO_ID_ES256K, 0x06));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidence(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data)
        );

        bytes32 sessionId = _sessionId(evidence.tpmQuoteReport, keccak256(evidence.teeReport.data));
        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(evidence.sessionKey);
        bytes32 delegationMessage = keccak256(
            abi.encode(
                DELEGATION_DOMAIN,
                block.chainid,
                address(sessionRegistry),
                oldPolicy.baseImageId,
                oldPolicy.workloadId,
                sessionId,
                sessionKeyFingerprint
            )
        );
        (, bytes memory possessionSignature) = abi.decode(evidence.sessionKeySignature, (bytes, bytes));
        vm.mockCall(
            address(signatureVerifier),
            abi.encodeCall(ISignatureVerifier.verify, (evidence.sessionKey, delegationMessage, possessionSignature)),
            abi.encode(false)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.SessionKeyPossessionFailed.selector, delegationMessage, sessionKeyFingerprint
            )
        );
        sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function testSessionFingerprintCannotBeClaimedByAnotherActiveSessionAndClearsOnRevoke() public {
        PublicIdentity memory sessionKey = _identity(ALGO_ID_ES256K, 0x08);
        AttestationEvidence memory firstEvidence = _fullEvidence(0x07, sessionKey);
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidence(
            firstEvidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(firstEvidence.teeReport.data)
        );
        bytes32 firstSessionId = sessionRegistry.registerSession(
            firstEvidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
        bytes32 sessionKeyFingerprint = LibKey.computeKeyFingerprint(sessionKey);
        assertEq(sessionRegistry.getSessionId(sessionKeyFingerprint), firstSessionId);

        AttestationEvidence memory secondEvidence = _fullEvidence(0x09, sessionKey);
        _mockFullEvidence(
            secondEvidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(secondEvidence.teeReport.data)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.SessionFingerprintInUse.selector, sessionKeyFingerprint, firstSessionId
            )
        );
        sessionRegistry.registerSession(
            secondEvidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );

        sessionRegistry.revokeSession(firstSessionId, uint64(block.timestamp + 5 minutes), ownerIdentity, hex"01");
        assertEq(sessionRegistry.getSessionId(sessionKeyFingerprint), bytes32(0));
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

    function testTeeAttributePolicyMatrices() public {
        bytes32[3] memory keys =
            [TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA];
        uint256[3] memory bits = [
            TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
            TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
            TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT
        ];

        for (uint256 keyIndex = 0; keyIndex < keys.length; keyIndex++) {
            TEEType teeType = keyIndex == 0 ? TEEType.IntelTDX : TEEType.AmdSevSnp;
            for (uint256 actualMode = 0; actualMode < 2; actualMode++) {
                bool actual = actualMode == 1;
                for (uint256 baseMode = 0; baseMode < 3; baseMode++) {
                    for (uint256 workloadMode = 0; workloadMode < 3; workloadMode++) {
                        PolicyIds memory policy = _registerTeePolicy(keys[keyIndex], baseMode, workloadMode, 0, 0);
                        uint8 evidenceMarker = uint8(nextTeePolicyVersion);
                        AttestationEvidence memory evidence =
                            _fullEvidence(evidenceMarker, _identity(ALGO_ID_ES256K, evidenceMarker));
                        evidence.teeReport.teeType = teeType;
                        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
                        uint256 nonce = sessionRegistry.getNonce(ownerFingerprint);
                        _mockFullEvidenceWithResult(
                            evidence,
                            ownerFingerprint,
                            nonce,
                            oldAk,
                            oldTpmSigningKey,
                            keccak256(evidence.teeReport.data),
                            TeeVerificationResult({
                                valid: true,
                                reportData: "",
                                teeType: teeType,
                                enabledTeeAttributes: actual ? bits[keyIndex] : 0,
                                intelTdxTcbStatusBit: teeType == TEEType.IntelTDX ? TDX_TCB_STATUS_OK : 0,
                                amdSevSnpTcbValues: bytes32(0),
                                amdSevSnpPlatformInfo: 0,
                                amdSevSnpCpuid: teeType == TEEType.AmdSevSnp ? 0x191101 : 0,
                                amdSevSnpReportVersion: teeType == TEEType.AmdSevSnp ? 3 : 0,
                                amdSevSnpLaunchMitigationVector: 0,
                                amdSevSnpCurrentMitigationVector: 0
                            })
                        );

                        bool baseMatches = actual ? baseMode == 2 : baseMode != 2;
                        bool workloadPermits = !actual || workloadMode == 2;
                        if (!baseMatches) {
                            bytes32 declaredValue = baseMode == 2 ? TEE_ATTRIBUTE_TRUE : bytes32(0);
                            vm.expectRevert(
                                abi.encodeWithSelector(
                                    SessionRegistry.TeeAttributeBaseImageMismatch.selector,
                                    keys[keyIndex],
                                    declaredValue,
                                    actual ? TEE_ATTRIBUTE_TRUE : bytes32(0)
                                )
                            );
                        } else if (!workloadPermits) {
                            vm.expectRevert(
                                abi.encodeWithSelector(
                                    SessionRegistry.TeeAttributeValueNotAllowed.selector,
                                    keys[keyIndex],
                                    TEE_ATTRIBUTE_TRUE
                                )
                            );
                        }

                        bytes32 sessionId = sessionRegistry.registerSession(
                            evidence,
                            policy.workloadId,
                            policy.baseImageId,
                            policy.platformProfileId,
                            policy.measurementVariantId,
                            uint64(block.timestamp + 5 minutes),
                            ownerIdentity,
                            hex"01"
                        );
                        if (baseMatches && workloadPermits) {
                            assertTrue(sessionRegistry.isSessionActive(sessionId));
                        }
                    }
                }
            }
        }
    }

    function testTeeAttributeVariantOverridesProfile() public {
        _assertVariantOverride(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, 1, 2, true);
        _assertVariantOverride(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, 2, 1, false);
    }

    function testTdxTcbStatusVariantOverridesProfile() public {
        PolicyIds memory policy = _registerTdxTcbPolicyWithVariant(1, 2, 2);
        AttestationEvidence memory evidence =
            _fullEvidence(uint8(nextTeePolicyVersion), _identity(ALGO_ID_ES256K, 0xd1));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: "",
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_CONFIGURATION_NEEDED,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            })
        );

        bytes32 sessionId = sessionRegistry.registerSession(
            evidence,
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
        assertTrue(sessionRegistry.isSessionActive(sessionId));
    }

    function testRotateKeyInheritsPreviouslyVerifiedTeeAttributes() public {
        PolicyIds memory policy = _registerTeePolicy(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, 2, 2, 0, 1 days);
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 oldSessionId = keccak256("verified-debug-session");
        _seedSession(
            oldSessionId,
            false,
            uint64(block.timestamp + 12 hours),
            ownerFingerprint,
            oldAk,
            oldTpmSigningKey,
            oldSessionKey,
            policy
        );

        PublicIdentity memory newTpmSigningKey = _identity(ALGO_ID_ES256, 0xc1);
        PublicIdentity memory newSessionKey = _identity(ALGO_ID_ES256K, 0xc2);
        SessionKeyRotationEvidence memory evidence = _rotationEvidence(0xc3, oldAk, oldTpmSigningKey, newSessionKey);
        _mockQuote(ownerFingerprint, 0);
        _mockCertifiedKey(newTpmSigningKey);

        bytes32 newSessionId = sessionRegistry.rotateKey(
            oldSessionId,
            keccak256("verified-debug-tee-report"),
            evidence,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );

        assertTrue(sessionRegistry.isSessionActive(newSessionId));
        _assertPolicy(sessionRegistry.getSession(newSessionId), policy);
    }

    function testNonSelectedTeeAttributesAreNotEvaluated() public {
        PolicyIds memory policy = _registerTeePolicy(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, 2, 2, 0, 0);
        AttestationEvidence memory evidence = _fullEvidence(0xe1, _identity(ALGO_ID_ES256K, 0xe2));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: "",
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            })
        );

        sessionRegistry.registerSession(
            evidence,
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function testTdxTcbStatusPolicyMatrices() public {
        uint256[2] memory actualStatuses = [TDX_TCB_STATUS_OK, TDX_TCB_STATUS_CONFIGURATION_NEEDED];
        for (uint256 actualIndex = 0; actualIndex < actualStatuses.length; actualIndex++) {
            uint256 actualStatus = actualStatuses[actualIndex];
            for (uint256 baseMode = 0; baseMode < 3; baseMode++) {
                for (uint256 workloadMode = 0; workloadMode < 3; workloadMode++) {
                    PolicyIds memory policy = _registerTdxTcbPolicy(baseMode, workloadMode);
                    uint8 evidenceMarker = uint8(nextTeePolicyVersion);
                    AttestationEvidence memory evidence =
                        _fullEvidence(evidenceMarker, _identity(ALGO_ID_ES256K, evidenceMarker));
                    bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
                    _mockFullEvidenceWithResult(
                        evidence,
                        ownerFingerprint,
                        sessionRegistry.getNonce(ownerFingerprint),
                        oldAk,
                        oldTpmSigningKey,
                        keccak256(evidence.teeReport.data),
                        TeeVerificationResult({
                            valid: true,
                            reportData: "",
                            teeType: TEEType.IntelTDX,
                            enabledTeeAttributes: 0,
                            intelTdxTcbStatusBit: actualStatus,
                            amdSevSnpTcbValues: bytes32(0),
                            amdSevSnpPlatformInfo: 0,
                            amdSevSnpCpuid: 0,
                            amdSevSnpReportVersion: 0,
                            amdSevSnpLaunchMitigationVector: 0,
                            amdSevSnpCurrentMitigationVector: 0
                        })
                    );

                    bool basePermits = actualStatus == TDX_TCB_STATUS_OK || baseMode == 2;
                    bool workloadPermits = actualStatus == TDX_TCB_STATUS_OK || workloadMode == 2;
                    if (!basePermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                SessionRegistry.TeeAttributeBaseImageMismatch.selector,
                                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                                bytes32(TDX_TCB_STATUS_OK),
                                bytes32(actualStatus)
                            )
                        );
                    } else if (!workloadPermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                SessionRegistry.TeeAttributeValueNotAllowed.selector,
                                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                                bytes32(actualStatus)
                            )
                        );
                    }

                    bytes32 sessionId = sessionRegistry.registerSession(
                        evidence,
                        policy.workloadId,
                        policy.baseImageId,
                        policy.platformProfileId,
                        policy.measurementVariantId,
                        uint64(block.timestamp + 5 minutes),
                        ownerIdentity,
                        hex"01"
                    );
                    if (basePermits && workloadPermits) {
                        assertTrue(sessionRegistry.isSessionActive(sessionId));
                    }
                }
            }
        }
    }

    function testSnpDoesNotEvaluateTdxTcbStatusPolicy() public {
        PolicyIds memory policy = _registerTdxTcbPolicy(2, 2);
        AttestationEvidence memory evidence = _fullEvidence(0xd8, _identity(ALGO_ID_ES256K, 0xd9));
        evidence.teeReport.teeType = TEEType.AmdSevSnp;
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: "",
                teeType: TEEType.AmdSevSnp,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: 0,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0x191101,
                amdSevSnpReportVersion: 3,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            })
        );

        bytes32 sessionId = sessionRegistry.registerSession(
            evidence,
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
        assertTrue(sessionRegistry.isSessionActive(sessionId));
    }

    function testAmdSnpRegistryDefaultTcbPolicyRunsDuringFullRegistration() public {
        bytes32 minimumTcb = 0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004;
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = AmdSnpSecurityPolicyUpdate(0x191101, 1, 2, true, minimumTcb, bytes32(0), 0, 0);
        amdSnpSecurityPolicyRegistry.updatePolicies(updates, keccak256("full-registration-policy"));

        AttestationEvidence memory evidence = _fullEvidence(0xda, _identity(ALGO_ID_ES256K, 0xdb));
        evidence.teeReport.teeType = TEEType.AmdSevSnp;
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        TeeVerificationResult memory result = TeeVerificationResult({
            valid: true,
            reportData: "",
            teeType: TEEType.AmdSevSnp,
            enabledTeeAttributes: 0,
            intelTdxTcbStatusBit: 0,
            amdSevSnpTcbValues: minimumTcb,
            amdSevSnpPlatformInfo: 0,
            amdSevSnpCpuid: 0x191101,
            amdSevSnpReportVersion: 3,
            amdSevSnpLaunchMitigationVector: 0,
            amdSevSnpCurrentMitigationVector: 0
        });
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            result
        );

        bytes32 sessionId = sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
        assertTrue(sessionRegistry.isSessionActive(sessionId));

        evidence = _fullEvidence(0xdc, _identity(ALGO_ID_ES256K, 0xdd));
        evidence.teeReport.teeType = TEEType.AmdSevSnp;
        result.amdSevSnpTcbValues = bytes32(uint256(minimumTcb) - 1);
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            result
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                minimumTcb,
                result.amdSevSnpTcbValues
            )
        );
        sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function testValidFalseFailsForAzureAndGcpRegistration() public {
        for (uint256 collateralType = 0; collateralType < 2; collateralType++) {
            AttestationEvidence memory evidence =
                _fullEvidence(uint8(0xf0 + collateralType), _identity(ALGO_ID_ES256K, uint8(0xf2 + collateralType)));
            evidence.akPubCollateral.akPubCollateralType =
                collateralType == 0 ? AkPubCollateralType.AzureMaaJwt : AkPubCollateralType.GcpCertChain;
            bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
            _mockFullEvidenceWithResult(
                evidence,
                ownerFingerprint,
                0,
                oldAk,
                oldTpmSigningKey,
                keccak256(evidence.teeReport.data),
                TeeVerificationResult({
                    valid: false,
                    reportData: "",
                    teeType: TEEType.IntelTDX,
                    enabledTeeAttributes: 0,
                    intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                    amdSevSnpTcbValues: bytes32(0),
                    amdSevSnpPlatformInfo: 0,
                    amdSevSnpCpuid: 0,
                    amdSevSnpReportVersion: 0,
                    amdSevSnpLaunchMitigationVector: 0,
                    amdSevSnpCurrentMitigationVector: 0
                })
            );

            vm.expectRevert(SessionRegistry.TeeVerificationFailed.selector);
            sessionRegistry.registerSession(
                evidence,
                oldPolicy.workloadId,
                oldPolicy.baseImageId,
                oldPolicy.platformProfileId,
                oldPolicy.measurementVariantId,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"01"
            );
        }
    }

    function testAkCollateralValidFalseFailsForAzureAndGcpRegistration() public {
        for (uint256 collateralType = 0; collateralType < 2; collateralType++) {
            AttestationEvidence memory evidence =
                _fullEvidence(uint8(0xe0 + collateralType), _identity(ALGO_ID_ES256K, uint8(0xe2 + collateralType)));
            evidence.akPubCollateral.akPubCollateralType =
                collateralType == 0 ? AkPubCollateralType.AzureMaaJwt : AkPubCollateralType.GcpCertChain;
            bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
            _mockFullEvidence(
                evidence,
                ownerFingerprint,
                sessionRegistry.getNonce(ownerFingerprint),
                oldAk,
                oldTpmSigningKey,
                keccak256(evidence.teeReport.data)
            );
            vm.mockCall(
                AK_COLLATERAL_VERIFIER,
                abi.encodeCall(IAkCollateralVerifier.verifyAkCollateral, (evidence.akPubCollateral)),
                abi.encode(
                    AkCollateralVerificationResult({
                        valid: false,
                        akPub: oldAk,
                        akPubFingerprint: LibKey.computeKeyFingerprint(oldAk),
                        teeType: evidence.teeReport.teeType,
                        bindingHash: bytes32(0)
                    })
                )
            );

            vm.expectRevert(SessionRegistry.AkCollateralVerificationFailed.selector);
            sessionRegistry.registerSession(
                evidence,
                oldPolicy.workloadId,
                oldPolicy.baseImageId,
                oldPolicy.platformProfileId,
                oldPolicy.measurementVariantId,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"01"
            );
        }
    }

    function testAzureReportDataMustMatchMaaBindingHashForTdxAndSnp() public {
        for (uint256 teeIndex = 0; teeIndex < 2; teeIndex++) {
            TEEType teeType = teeIndex == 0 ? TEEType.IntelTDX : TEEType.AmdSevSnp;
            AttestationEvidence memory evidence =
                _fullEvidence(uint8(0xb0 + teeIndex), _identity(ALGO_ID_ES256K, uint8(0xb2 + teeIndex)));
            evidence.teeReport.teeType = teeType;
            bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
            bytes32 expectedBindingHash = keccak256(abi.encode("expected Azure HCL binding", teeIndex));
            bytes32 actualBindingHash = keccak256(abi.encode("different Azure HCL binding", teeIndex));
            bytes memory reportData = _azureReportData(teeType, actualBindingHash, bytes32(0));
            _mockFullEvidenceWithBindingResult(
                evidence,
                ownerFingerprint,
                sessionRegistry.getNonce(ownerFingerprint),
                oldAk,
                oldTpmSigningKey,
                keccak256(evidence.teeReport.data),
                TeeVerificationResult({
                    valid: true,
                    reportData: reportData,
                    teeType: teeType,
                    enabledTeeAttributes: 0,
                    intelTdxTcbStatusBit: teeType == TEEType.IntelTDX ? TDX_TCB_STATUS_OK : 0,
                    amdSevSnpTcbValues: bytes32(0),
                    amdSevSnpPlatformInfo: 0,
                    amdSevSnpCpuid: teeType == TEEType.AmdSevSnp ? 0x191101 : 0,
                    amdSevSnpReportVersion: teeType == TEEType.AmdSevSnp ? 3 : 0,
                    amdSevSnpLaunchMitigationVector: 0,
                    amdSevSnpCurrentMitigationVector: 0
                }),
                expectedBindingHash
            );

            vm.expectRevert(
                abi.encodeWithSelector(
                    SessionRegistry.AzureTeeReportDataMismatch.selector,
                    actualBindingHash,
                    expectedBindingHash,
                    bytes32(0)
                )
            );
            sessionRegistry.registerSession(
                evidence,
                oldPolicy.workloadId,
                oldPolicy.baseImageId,
                oldPolicy.platformProfileId,
                oldPolicy.measurementVariantId,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"01"
            );
        }
    }

    function testAzureReportDataAcceptsMaaBindingHashForTdxAndSnp() public {
        for (uint256 teeIndex = 0; teeIndex < 2; teeIndex++) {
            TEEType teeType = teeIndex == 0 ? TEEType.IntelTDX : TEEType.AmdSevSnp;
            AttestationEvidence memory evidence =
                _fullEvidence(uint8(0xc0 + teeIndex), _identity(ALGO_ID_ES256K, uint8(0xc2 + teeIndex)));
            evidence.teeReport.teeType = teeType;
            bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
            bytes32 bindingHash = keccak256(abi.encode("Azure HCL binding", teeIndex));
            _mockFullEvidenceWithBindingResult(
                evidence,
                ownerFingerprint,
                sessionRegistry.getNonce(ownerFingerprint),
                oldAk,
                oldTpmSigningKey,
                keccak256(evidence.teeReport.data),
                TeeVerificationResult({
                    valid: true,
                    reportData: _azureReportData(teeType, bindingHash, bytes32(0)),
                    teeType: teeType,
                    enabledTeeAttributes: 0,
                    intelTdxTcbStatusBit: teeType == TEEType.IntelTDX ? TDX_TCB_STATUS_OK : 0,
                    amdSevSnpTcbValues: bytes32(0),
                    amdSevSnpPlatformInfo: 0,
                    amdSevSnpCpuid: teeType == TEEType.AmdSevSnp ? 0x191101 : 0,
                    amdSevSnpReportVersion: teeType == TEEType.AmdSevSnp ? 3 : 0,
                    amdSevSnpLaunchMitigationVector: 0,
                    amdSevSnpCurrentMitigationVector: 0
                }),
                bindingHash
            );

            bytes32 sessionId = sessionRegistry.registerSession(
                evidence,
                oldPolicy.workloadId,
                oldPolicy.baseImageId,
                oldPolicy.platformProfileId,
                oldPolicy.measurementVariantId,
                uint64(block.timestamp + 5 minutes),
                ownerIdentity,
                hex"01"
            );
            assertTrue(sessionRegistry.isSessionActive(sessionId));
        }
    }

    function testAzureRejectsMaaTeeTypeThatDiffersFromVerifiedReport() public {
        AttestationEvidence memory evidence = _fullEvidence(0xca, _identity(ALGO_ID_ES256K, 0xcb));
        evidence.teeReport.teeType = TEEType.IntelTDX;
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 bindingHash = keccak256("Azure HCL binding");
        _mockFullEvidenceWithBindingResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: _azureReportData(TEEType.IntelTDX, bindingHash, bytes32(0)),
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            }),
            bindingHash
        );
        vm.mockCall(
            AK_COLLATERAL_VERIFIER,
            abi.encodeCall(IAkCollateralVerifier.verifyAkCollateral, (evidence.akPubCollateral)),
            abi.encode(
                AkCollateralVerificationResult({
                    valid: true,
                    akPub: oldAk,
                    akPubFingerprint: LibKey.computeKeyFingerprint(oldAk),
                    teeType: TEEType.AmdSevSnp,
                    bindingHash: bindingHash
                })
            )
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.AzureMaaTeeTypeMismatch.selector, TEEType.IntelTDX, TEEType.AmdSevSnp
            )
        );
        sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function testAzureReportDataRejectsNonzeroPadding() public {
        AttestationEvidence memory evidence = _fullEvidence(0xd0, _identity(ALGO_ID_ES256K, 0xd2));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 bindingHash = keccak256("Azure HCL binding");
        bytes32 padding = bytes32(uint256(1));
        _mockFullEvidenceWithBindingResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: _azureReportData(TEEType.IntelTDX, bindingHash, padding),
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            }),
            bindingHash
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                SessionRegistry.AzureTeeReportDataMismatch.selector, bindingHash, bindingHash, padding
            )
        );
        sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function testAzureReportDataRejectsShortVerifiedResult() public {
        AttestationEvidence memory evidence = _fullEvidence(0xd4, _identity(ALGO_ID_ES256K, 0xd6));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidenceWithBindingResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: hex"00",
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            }),
            bytes32(0)
        );

        vm.expectRevert(
            abi.encodeWithSelector(SessionRegistry.AzureTeeReportDataTooShort.selector, uint256(1), uint256(584))
        );
        sessionRegistry.registerSession(
            evidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function _assertVariantOverride(bytes32 key, uint256 profileMode, uint256 variantMode, bool actual) private {
        PolicyIds memory policy = _registerTeePolicy(key, profileMode, 2, variantMode, 0);
        uint8 evidenceMarker = uint8(nextTeePolicyVersion);
        AttestationEvidence memory evidence = _fullEvidence(evidenceMarker, _identity(ALGO_ID_ES256K, evidenceMarker));
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            sessionRegistry.getNonce(ownerFingerprint),
            oldAk,
            oldTpmSigningKey,
            keccak256(evidence.teeReport.data),
            TeeVerificationResult({
                valid: true,
                reportData: "",
                teeType: TEEType.IntelTDX,
                enabledTeeAttributes: actual ? TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT : 0,
                intelTdxTcbStatusBit: TDX_TCB_STATUS_OK,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: 0,
                amdSevSnpReportVersion: 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            })
        );

        sessionRegistry.registerSession(
            evidence,
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            uint64(block.timestamp + 5 minutes),
            ownerIdentity,
            hex"01"
        );
    }

    function _registerTeePolicy(bytes32 key, uint256 profileMode, uint256 workloadMode, uint256 variantMode, uint64 ttl)
        private
        returns (PolicyIds memory ids)
    {
        nextTeePolicyVersion++;
        string memory version = vm.toString(nextTeePolicyVersion);
        BaseImageSpec memory baseImage = BaseImageSpec({name: "tee-policy-base", version: version, uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "test-platform", invariants: new PcrSpec[](0), attributes: _teeAttributes(key, profileMode)
        });
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: "test-variant", overridePcrs: new PcrSpec[](0), attributes: _teeAttributes(key, variantMode)
        });
        ids.baseImageId = baseImageRegistry.registerBaseImage(
            baseImage, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
        ids.platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, ids.baseImageId, profiles[0].name));
        ids.measurementVariantId =
            keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, ids.platformProfileId, variants[0][0].name));

        bytes32[] memory allowedBaseImages = new bytes32[](1);
        allowedBaseImages[0] = ids.baseImageId;
        WorkloadSpec memory workload = WorkloadSpec({
            name: "tee-policy-workload",
            version: version,
            sessionTtl: ttl,
            baseImageMode: AccessMode.WHITELIST,
            baseImageIds: allowedBaseImages,
            requirements: _teeRequirements(key, workloadMode),
            pcrs: new PcrSpec[](0)
        });
        ids.workloadId =
            workloadRegistry.registerWorkload(workload, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
        ids.sessionTtl = ttl;
    }

    function _registerTdxTcbPolicy(uint256 profileMode, uint256 workloadMode) private returns (PolicyIds memory ids) {
        return _registerTdxTcbPolicyWithVariant(profileMode, 0, workloadMode);
    }

    function _registerTdxTcbPolicyWithVariant(uint256 profileMode, uint256 variantMode, uint256 workloadMode)
        private
        returns (PolicyIds memory ids)
    {
        nextTeePolicyVersion++;
        string memory version = vm.toString(nextTeePolicyVersion);
        bytes32 relaxedMask = bytes32(TDX_TCB_STATUS_OK | TDX_TCB_STATUS_CONFIGURATION_NEEDED);

        Attribute[] memory attributes = new Attribute[](profileMode == 0 ? 0 : 1);
        if (profileMode != 0) {
            attributes[0] = Attribute({
                key: TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                value: profileMode == 2 ? relaxedMask : bytes32(TDX_TCB_STATUS_OK)
            });
        }
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({name: "test-platform", invariants: new PcrSpec[](0), attributes: attributes});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        Attribute[] memory variantAttributes = new Attribute[](variantMode == 0 ? 0 : 1);
        if (variantMode != 0) {
            variantAttributes[0] = Attribute({
                key: TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                value: variantMode == 2 ? relaxedMask : bytes32(TDX_TCB_STATUS_OK)
            });
        }
        variants[0][0] =
            MeasurementVariant({name: "test-variant", overridePcrs: new PcrSpec[](0), attributes: variantAttributes});
        BaseImageSpec memory baseImage = BaseImageSpec({name: "tdx-tcb-base", version: version, uri: ""});
        ids.baseImageId = baseImageRegistry.registerBaseImage(
            baseImage, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
        ids.platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, ids.baseImageId, profiles[0].name));
        ids.measurementVariantId =
            keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, ids.platformProfileId, variants[0][0].name));

        AttributeRequirement[] memory requirements = new AttributeRequirement[](workloadMode == 0 ? 0 : 1);
        if (workloadMode != 0) {
            bytes32[] memory allowedValues = new bytes32[](1);
            allowedValues[0] = workloadMode == 2 ? relaxedMask : bytes32(TDX_TCB_STATUS_OK);
            requirements[0] =
                AttributeRequirement({key: TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, allowedValues: allowedValues});
        }
        bytes32[] memory allowedBaseImages = new bytes32[](1);
        allowedBaseImages[0] = ids.baseImageId;
        WorkloadSpec memory workload = WorkloadSpec({
            name: "tdx-tcb-workload",
            version: version,
            sessionTtl: 0,
            baseImageMode: AccessMode.WHITELIST,
            baseImageIds: allowedBaseImages,
            requirements: requirements,
            pcrs: new PcrSpec[](0)
        });
        ids.workloadId =
            workloadRegistry.registerWorkload(workload, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
    }

    function _teeAttributes(bytes32 key, uint256 mode) private pure returns (Attribute[] memory attributes) {
        attributes = new Attribute[](mode == 0 ? 0 : 1);
        if (mode != 0) {
            attributes[0] = Attribute({key: key, value: mode == 2 ? TEE_ATTRIBUTE_TRUE : bytes32(0)});
        }
    }

    function _teeRequirements(bytes32 key, uint256 mode)
        private
        pure
        returns (AttributeRequirement[] memory requirements)
    {
        requirements = new AttributeRequirement[](mode == 0 ? 0 : 1);
        if (mode == 0) return requirements;
        bytes32[] memory allowedValues = new bytes32[](mode == 2 ? 2 : 1);
        allowedValues[0] = bytes32(0);
        if (mode == 2) allowedValues[1] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement({key: key, allowedValues: allowedValues});
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
        evidence.sessionKeySignature =
            abi.encode(abi.encodePacked("delegation-", marker), abi.encodePacked("possession-", marker));
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
        evidence.sessionKeySignature =
            abi.encode(abi.encodePacked("delegation-", marker), abi.encodePacked("possession-", marker));
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
        _mockFullEvidenceWithResult(
            evidence,
            ownerFingerprint,
            nonce,
            akPub,
            certifiedTpmSigningKey,
            teeReportHash,
            TeeVerificationResult({
                valid: true,
                reportData: "",
                teeType: evidence.teeReport.teeType,
                enabledTeeAttributes: 0,
                intelTdxTcbStatusBit: evidence.teeReport.teeType == TEEType.IntelTDX ? TDX_TCB_STATUS_OK : 0,
                amdSevSnpTcbValues: bytes32(0),
                amdSevSnpPlatformInfo: 0,
                amdSevSnpCpuid: evidence.teeReport.teeType == TEEType.AmdSevSnp ? 0x191101 : 0,
                amdSevSnpReportVersion: evidence.teeReport.teeType == TEEType.AmdSevSnp ? 3 : 0,
                amdSevSnpLaunchMitigationVector: 0,
                amdSevSnpCurrentMitigationVector: 0
            })
        );
    }

    function _mockFullEvidenceWithResult(
        AttestationEvidence memory evidence,
        bytes32 ownerFingerprint,
        uint256 nonce,
        PublicIdentity memory akPub,
        PublicIdentity memory certifiedTpmSigningKey,
        bytes32 teeReportHash,
        TeeVerificationResult memory teeResult
    ) private {
        _mockFullEvidenceWithBindingResult(
            evidence, ownerFingerprint, nonce, akPub, certifiedTpmSigningKey, teeReportHash, teeResult, bytes32(0)
        );
    }

    function _mockFullEvidenceWithBindingResult(
        AttestationEvidence memory evidence,
        bytes32 ownerFingerprint,
        uint256 nonce,
        PublicIdentity memory akPub,
        PublicIdentity memory certifiedTpmSigningKey,
        bytes32 teeReportHash,
        TeeVerificationResult memory teeResult,
        bytes32 bindingHash
    ) private {
        if (
            teeResult.valid && teeResult.reportData.length == 0
                && evidence.akPubCollateral.akPubCollateralType == AkPubCollateralType.AzureMaaJwt
        ) {
            teeResult.reportData = _azureReportData(teeResult.teeType, bindingHash, bytes32(0));
        }
        vm.mockCall(
            TEE_VERIFIER, abi.encodeCall(ITeeVerifier.verifyTeeReport, (evidence.teeReport)), abi.encode(teeResult)
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
                    teeType: teeResult.teeType,
                    bindingHash: bindingHash
                })
            )
        );
        _mockQuote(ownerFingerprint, nonce);
        _mockCertifiedKey(certifiedTpmSigningKey);
    }

    function _azureReportData(TEEType teeType, bytes32 bindingHash, bytes32 padding)
        private
        pure
        returns (bytes memory reportData)
    {
        uint256 reportSize = teeType == TEEType.IntelTDX ? 584 : 1184;
        uint256 reportDataOffset = teeType == TEEType.IntelTDX ? 520 : 0x50;
        reportData = new bytes(reportSize);
        assembly ("memory-safe") {
            mstore(add(add(reportData, 0x20), reportDataOffset), bindingHash)
            mstore(add(add(reportData, 0x40), reportDataOffset), padding)
        }
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
