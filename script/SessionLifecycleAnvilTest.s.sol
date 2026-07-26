// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {AmdSnpSecurityPolicyUpdate} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
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
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TDX_TCB_STATUS_OK,
    TEE_ATTRIBUTE_TRUE
} from "../src/types/Constants.sol";

/// @dev Transaction-path mock only. It authenticates no hardware evidence.
contract AnvilLifecycleTeeVerifier is ITeeVerifier {
    error TdxMigrationServiceTdNotSupported();
    error SnpMigrationAgentNotSupported();

    bool private _valid;
    TEEType private _teeType;
    uint256 private _enabledTeeAttributes;
    uint8 private _rejection;

    function configure(bool valid, TEEType teeType, uint256 enabledTeeAttributes, uint8 rejection) external {
        _valid = valid;
        _teeType = teeType;
        _enabledTeeAttributes = enabledTeeAttributes;
        _rejection = rejection;
    }

    function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32) {
        return keccak256(teeReport.data);
    }

    function verifyTeeReport(TeeReport memory) external view returns (TeeVerificationResult memory result) {
        if (_rejection == 1) revert TdxMigrationServiceTdNotSupported();
        if (_rejection == 2) revert SnpMigrationAgentNotSupported();
        bytes memory reportData = _teeType == TEEType.IntelTDX ? new bytes(584) : new bytes(1184);
        return TeeVerificationResult({
            valid: _valid,
            reportData: reportData,
            teeType: _teeType,
            enabledTeeAttributes: _enabledTeeAttributes,
            intelTdxTcbStatusBit: _teeType == TEEType.IntelTDX ? TDX_TCB_STATUS_OK : 0,
            amdSevSnpTcbValues: bytes32(0),
            amdSevSnpPlatformInfo: 0,
            amdSevSnpCpuid: _teeType == TEEType.AmdSevSnp ? 0x191101 : 0
        });
    }

    function extractDcapReportData(bytes memory) external pure returns (bytes memory) {
        return "";
    }

    function extractSnpReportData(bytes memory) external pure returns (bytes memory) {
        return "";
    }
}

/// @dev Transaction-path mock only. The test sets the AK returned for the next operation.
contract AnvilLifecycleAkVerifier is IAkCollateralVerifier {
    PublicIdentity private _akPub;

    function setAk(PublicIdentity calldata akPub) external {
        _akPub = akPub;
    }

    function verifyAkCollateral(AkPubCollateral calldata)
        external
        view
        returns (AkCollateralVerificationResult memory result)
    {
        PublicIdentity memory akPub = _akPub;
        return AkCollateralVerificationResult({
            valid: true, akPub: akPub, akPubFingerprint: LibKey.computeKeyFingerprint(akPub), bindingHash: bytes32(0)
        });
    }
}

/// @dev Transaction-path mock only. It preserves SessionRegistry nonce and key-flow checks.
contract AnvilLifecycleTpmVerifier is ITpmAttestation {
    bytes private _extraData;
    CertPubkey private _certifiedKey;

    function configure(bytes calldata extraData, PublicIdentity calldata certifiedKey) external {
        _extraData = extraData;
        _certifiedKey = CertPubkey({algo: 0x0023, params: 0x0003, data: certifiedKey.key});
    }

    function verifyTpmQuote(bytes calldata, bytes calldata, bytes[] calldata)
        external
        view
        returns (bool success, bytes memory akPubkey, bytes memory extraData)
    {
        return (true, "", _extraData);
    }

    function verifyTpmQuoteWithTrustedAkPub(bytes calldata, bytes calldata, CertPubkey calldata)
        external
        view
        returns (bool success, bytes memory extraData)
    {
        return (true, _extraData);
    }

    function verifyTpmKeyCertification(bytes calldata, bytes calldata, bytes calldata, CertPubkey calldata, uint32)
        external
        view
        returns (CertPubkey memory certifiedPubkey, bytes memory extraData)
    {
        return (_certifiedKey, "");
    }

    function extractExtraData(bytes calldata) external pure returns (bool success, bytes memory extraData) {
        return (true, "");
    }

    function checkPcrMeasurements(bytes calldata, PcrValue[] calldata)
        external
        view
        returns (bool success, bytes memory extraData)
    {
        return (true, _extraData);
    }

    function p256() external pure returns (address) {
        return address(0x100);
    }

    function addCA(bytes calldata) external {}

    function removeCA(bytes calldata) external {}

    function isCertificateRevoked(bytes calldata) external pure returns (bool) {
        return false;
    }

    function removeIntermediateCerts(bytes32[] calldata) external {}

    function updateCRL(bytes calldata, bytes calldata) external {}

    function verifyCertSignature(bytes calldata, CertPubkey memory) external pure returns (bool) {
        return true;
    }

    function verifyCertChain(bytes[] calldata) external pure returns (CertPubkey memory) {
        return CertPubkey({algo: 0, params: 0, data: ""});
    }

    function verifiedCA(bytes32) external pure returns (bool) {
        return true;
    }
}

/// @dev Keeps expected registration failures inside a successful Anvil transaction.
contract AnvilExpectedRevertProbe {
    function expectRevert(address target, bytes calldata callData, bytes4 expectedSelector) external {
        (bool success, bytes memory reason) = target.call(callData);
        require(!success, "registration unexpectedly succeeded");
        require(reason.length >= 4, "registration returned no error selector");

        bytes4 actualSelector;
        assembly ("memory-safe") {
            actualSelector := mload(add(reason, 0x20))
        }
        require(actualSelector == expectedSelector, "registration returned the wrong error");
    }
}

contract SessionLifecycleAnvilTest is Script {
    struct PolicyIds {
        bytes32 baseImageId;
        bytes32 workloadId;
        bytes32 platformProfileId;
        bytes32 measurementVariantId;
        uint64 sessionTtl;
    }

    MockSignatureVerifier private signatureVerifier;
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;
    AmdSnpSecurityPolicyRegistry private amdSnpSecurityPolicyRegistry;
    AnvilLifecycleTeeVerifier private teeVerifier;
    AnvilLifecycleTpmVerifier private tpmVerifier;
    AnvilLifecycleAkVerifier private akVerifier;
    SessionRegistry private sessionRegistry;
    AnvilExpectedRevertProbe private expectedRevertProbe;

    PublicIdentity private ownerIdentity;

    function run() external {
        vm.startBroadcast();

        ownerIdentity = _identity(ALGO_ID_ES256K, 0x01);
        signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        AmdSnpSecurityPolicyRegistry amdPolicyImplementation = new AmdSnpSecurityPolicyRegistry();
        amdSnpSecurityPolicyRegistry = AmdSnpSecurityPolicyRegistry(
            address(
                new ERC1967Proxy(
                    address(amdPolicyImplementation),
                    abi.encodeCall(AmdSnpSecurityPolicyRegistry.initialize, (vm.envAddress("OWNER")))
                )
            )
        );
        AmdSnpSecurityPolicyUpdate[] memory amdPolicies = new AmdSnpSecurityPolicyUpdate[](1);
        amdPolicies[0] = AmdSnpSecurityPolicyUpdate(0x191101, 1, true, bytes32(0), bytes32(0));
        amdSnpSecurityPolicyRegistry.updatePolicies(amdPolicies, keccak256("anvil-test-policy"));
        teeVerifier = new AnvilLifecycleTeeVerifier();
        teeVerifier.configure(true, TEEType.IntelTDX, 0, 0);
        tpmVerifier = new AnvilLifecycleTpmVerifier();
        akVerifier = new AnvilLifecycleAkVerifier();
        sessionRegistry = new SessionRegistry(
            teeVerifier,
            tpmVerifier,
            signatureVerifier,
            akVerifier,
            baseImageRegistry,
            workloadRegistry,
            amdSnpSecurityPolicyRegistry
        );
        expectedRevertProbe = new AnvilExpectedRevertProbe();

        PolicyIds memory oldPolicy = _registerPolicy("anvil-base-v1", "anvil-workload-v1", 1 days);
        PolicyIds memory newPolicy = _registerPolicy("anvil-base-v2", "anvil-workload-v2", 7 days);

        PublicIdentity memory firstAk = _identity(ALGO_ID_ES256, 0x10);
        PublicIdentity memory firstTpm = _identity(ALGO_ID_ES256, 0x11);
        AttestationEvidence memory firstEvidence = _fullEvidence(0x12, _identity(ALGO_ID_ES256K, 0x13));
        _configureAttestation(firstAk, firstTpm, 0);
        bytes32 firstSessionId = sessionRegistry.registerSession(
            firstEvidence,
            oldPolicy.workloadId,
            oldPolicy.baseImageId,
            oldPolicy.platformProfileId,
            oldPolicy.measurementVariantId,
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );
        require(sessionRegistry.isSessionActive(firstSessionId), "registration failed");

        PublicIdentity memory rotatedTpm = _identity(ALGO_ID_ES256, 0x20);
        PublicIdentity memory rotatedSessionKey = _identity(ALGO_ID_ES256K, 0x21);
        SessionKeyRotationEvidence memory rotation = SessionKeyRotationEvidence({
            tpmQuoteReport: _quoteReport(0x22),
            tpmCertifyReport: _certifyReport(0x23),
            sessionKeySignature: hex"02",
            sessionKey: rotatedSessionKey,
            rotationSignature: hex"03",
            oldTpmSigningKey: firstTpm,
            akPub: firstAk
        });
        _configureAttestation(firstAk, rotatedTpm, 1);
        bytes32 rotatedSessionId = sessionRegistry.rotateKey(
            firstSessionId,
            keccak256(firstEvidence.teeReport.data),
            rotation,
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"04"
        );
        require(!sessionRegistry.isSessionActive(firstSessionId), "rotation did not revoke predecessor");
        require(sessionRegistry.isSessionActive(rotatedSessionId), "rotation successor inactive");
        require(
            sessionRegistry.getSession(rotatedSessionId).sessionExpiresAt
                == sessionRegistry.getSession(firstSessionId).sessionExpiresAt,
            "rotation extended session expiry"
        );

        PublicIdentity memory renewedAk = _identity(ALGO_ID_ES256, 0x30);
        PublicIdentity memory renewedTpm = _identity(ALGO_ID_ES256, 0x31);
        AttestationEvidence memory renewalEvidence = _fullEvidence(0x32, _identity(ALGO_ID_ES256K, 0x33));
        _configureAttestation(renewedAk, renewedTpm, 2);
        bytes32 renewedSessionId = sessionRegistry.renewSession(
            rotatedSessionId,
            renewalEvidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            SessionRenewalAuthorization({signature: hex"05", oldTpmSigningKey: rotatedTpm}),
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"06"
        );
        require(!sessionRegistry.isSessionActive(rotatedSessionId), "renewal did not revoke predecessor");
        require(sessionRegistry.isSessionActive(renewedSessionId), "renewal successor inactive");
        CVMSession memory renewedSession = sessionRegistry.getSession(renewedSessionId);
        require(renewedSession.akPubKeyFingerprint == LibKey.computeKeyFingerprint(renewedAk), "renewal AK unchanged");
        require(renewedSession.workloadId == newPolicy.workloadId, "renewal policy unchanged");

        PublicIdentity memory recoveredAk = _identity(ALGO_ID_ES256, 0x40);
        PublicIdentity memory recoveredTpm = _identity(ALGO_ID_ES256, 0x41);
        AttestationEvidence memory recoveryEvidence = _fullEvidence(0x42, _identity(ALGO_ID_ES256K, 0x43));
        _configureAttestation(recoveredAk, recoveredTpm, 3);
        bytes32 recoveredSessionId = sessionRegistry.recoverSession(
            firstSessionId,
            recoveryEvidence,
            newPolicy.workloadId,
            newPolicy.baseImageId,
            newPolicy.platformProfileId,
            newPolicy.measurementVariantId,
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"07"
        );
        require(sessionRegistry.isSessionActive(recoveredSessionId), "recovery successor inactive");
        require(
            sessionRegistry.getNonce(LibKey.computeKeyFingerprint(ownerIdentity)) == 4, "unexpected final owner nonce"
        );

        _runTeeAttributePolicyMatrix();

        console.log("SessionRegistry:", address(sessionRegistry));
        console.log("registered session:");
        console.logBytes32(firstSessionId);
        console.log("rotated session:");
        console.logBytes32(rotatedSessionId);
        console.log("renewed session:");
        console.logBytes32(renewedSessionId);
        console.log("recovered session:");
        console.logBytes32(recoveredSessionId);

        vm.stopBroadcast();
    }

    function _runTeeAttributePolicyMatrix() private {
        PolicyIds memory safeDefault = _registerTeePolicy("safe-default", bytes32(0), new bytes32[](0));
        _registerWithCurrentTeeResult(safeDefault, 0x50, 4);

        bytes32[] memory allowDebug = new bytes32[](2);
        allowDebug[0] = bytes32(0);
        allowDebug[1] = TEE_ATTRIBUTE_TRUE;
        PolicyIds memory debugAllowed = _registerTeePolicy("debug-allowed", TEE_ATTRIBUTE_TRUE, allowDebug);
        teeVerifier.configure(true, TEEType.IntelTDX, TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT, 0);
        _registerWithCurrentTeeResult(debugAllowed, 0x51, 5);

        bytes32[] memory falseOnly = new bytes32[](1);
        falseOnly[0] = bytes32(0);
        PolicyIds memory workloadVeto = _registerTeePolicy("workload-veto", TEE_ATTRIBUTE_TRUE, falseOnly);
        _expectRegisterRevert(workloadVeto, 0x52, 6, SessionRegistry.TeeAttributeValueNotAllowed.selector);

        PolicyIds memory baseMismatch = _registerTeePolicy("base-mismatch", bytes32(0), allowDebug);
        _expectRegisterRevert(baseMismatch, 0x53, 6, SessionRegistry.TeeAttributeBaseImageMismatch.selector);

        teeVerifier.configure(true, TEEType.IntelTDX, 0, 1);
        _expectRegisterRevert(
            safeDefault, 0x54, 6, AnvilLifecycleTeeVerifier.TdxMigrationServiceTdNotSupported.selector
        );

        teeVerifier.configure(true, TEEType.AmdSevSnp, 0, 2);
        AttestationEvidence memory snpEvidence = _fullEvidence(0x55, _identity(ALGO_ID_ES256K, 0x56));
        snpEvidence.teeReport.teeType = TEEType.AmdSevSnp;
        _configureAttestation(_identity(ALGO_ID_ES256, 0x57), _identity(ALGO_ID_ES256, 0x58), 6);
        _expectEvidenceRegisterRevert(
            snpEvidence, safeDefault, AnvilLifecycleTeeVerifier.SnpMigrationAgentNotSupported.selector
        );

        console.log("verified TEE attribute Anvil matrix: passed");
    }

    function _registerWithCurrentTeeResult(PolicyIds memory policy, uint8 marker, uint256 nonce) private {
        _configureAttestation(_identity(ALGO_ID_ES256, marker + 1), _identity(ALGO_ID_ES256, marker + 2), nonce);
        bytes32 sessionId = sessionRegistry.registerSession(
            _fullEvidence(marker, _identity(ALGO_ID_ES256K, marker + 3)),
            policy.workloadId,
            policy.baseImageId,
            policy.platformProfileId,
            policy.measurementVariantId,
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );
        require(sessionRegistry.isSessionActive(sessionId), "TEE attribute registration inactive");
    }

    function _expectRegisterRevert(PolicyIds memory policy, uint8 marker, uint256 nonce, bytes4 expectedSelector)
        private
    {
        _configureAttestation(_identity(ALGO_ID_ES256, marker + 1), _identity(ALGO_ID_ES256, marker + 2), nonce);
        _expectEvidenceRegisterRevert(
            _fullEvidence(marker, _identity(ALGO_ID_ES256K, marker + 3)), policy, expectedSelector
        );
    }

    function _expectEvidenceRegisterRevert(
        AttestationEvidence memory evidence,
        PolicyIds memory policy,
        bytes4 expectedSelector
    ) private {
        bytes memory callData = abi.encodeCall(
            SessionRegistry.registerSession,
            (
                evidence,
                policy.workloadId,
                policy.baseImageId,
                policy.platformProfileId,
                policy.measurementVariantId,
                uint64(block.timestamp + 1 hours),
                ownerIdentity,
                hex"01"
            )
        );
        expectedRevertProbe.expectRevert(address(sessionRegistry), callData, expectedSelector);
    }

    function _registerTeePolicy(string memory suffix, bytes32 baseValue, bytes32[] memory allowedValues)
        private
        returns (PolicyIds memory ids)
    {
        BaseImageSpec memory baseImage = BaseImageSpec({name: "anvil-tee-base", version: suffix, uri: ""});
        Attribute[] memory attributes;
        if (baseValue == bytes32(0) && allowedValues.length == 0) {
            attributes = new Attribute[](0);
        } else {
            attributes = new Attribute[](1);
            attributes[0] = Attribute({key: TEE_ATTRIBUTE_INTEL_TDX_DEBUG, value: baseValue});
        }
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({name: "anvil-tdx", invariants: new PcrSpec[](0), attributes: attributes});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] =
            MeasurementVariant({name: "anvil-variant", overridePcrs: new PcrSpec[](0), attributes: new Attribute[](0)});
        ids.baseImageId = baseImageRegistry.registerBaseImage(
            baseImage, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
        ids.platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, ids.baseImageId, profiles[0].name));
        ids.measurementVariantId =
            keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, ids.platformProfileId, variants[0][0].name));

        AttributeRequirement[] memory requirements;
        if (allowedValues.length == 0) {
            requirements = new AttributeRequirement[](0);
        } else {
            requirements = new AttributeRequirement[](1);
            requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_INTEL_TDX_DEBUG, allowedValues: allowedValues});
        }
        bytes32[] memory baseImages = new bytes32[](1);
        baseImages[0] = ids.baseImageId;
        WorkloadSpec memory workload = WorkloadSpec({
            name: "anvil-tee-workload",
            version: suffix,
            sessionTtl: 1 days,
            baseImageMode: AccessMode.WHITELIST,
            baseImageIds: baseImages,
            requirements: requirements,
            pcrs: new PcrSpec[](0)
        });
        ids.workloadId =
            workloadRegistry.registerWorkload(workload, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
        ids.sessionTtl = 1 days;
    }

    function _registerPolicy(string memory baseVersion, string memory workloadVersion, uint64 ttl)
        private
        returns (PolicyIds memory ids)
    {
        BaseImageSpec memory baseImage = BaseImageSpec({name: "anvil-lifecycle-base", version: baseVersion, uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] =
            PlatformProfile({name: "anvil-platform", invariants: new PcrSpec[](0), attributes: new Attribute[](0)});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] =
            MeasurementVariant({name: "anvil-variant", overridePcrs: new PcrSpec[](0), attributes: new Attribute[](0)});
        ids.baseImageId = baseImageRegistry.registerBaseImage(
            baseImage, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
        ids.platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, ids.baseImageId, profiles[0].name));
        ids.measurementVariantId =
            keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, ids.platformProfileId, variants[0][0].name));

        bytes32[] memory allowedBaseImages = new bytes32[](1);
        allowedBaseImages[0] = ids.baseImageId;
        WorkloadSpec memory workload = WorkloadSpec({
            name: "anvil-lifecycle-workload",
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

    function _configureAttestation(PublicIdentity memory akPub, PublicIdentity memory certifiedKey, uint256 nonce)
        private
    {
        bytes32 ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);
        bytes32 extraData = keccak256(
            abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(sessionRegistry), ownerFingerprint, nonce)
        );
        akVerifier.setAk(akPub);
        tpmVerifier.configure(abi.encodePacked(extraData), certifiedKey);
    }

    function _fullEvidence(uint8 marker, PublicIdentity memory sessionKey)
        private
        pure
        returns (AttestationEvidence memory evidence)
    {
        evidence.teeReport = TeeReport({
            verificationBackendType: VerificationBackendType.Solidity,
            teeType: TEEType.IntelTDX,
            data: abi.encodePacked("anvil-tee-", marker)
        });
        evidence.tpmQuoteReport = _quoteReport(marker);
        evidence.tpmCertifyReport = _certifyReport(marker);
        evidence.akPubCollateral = AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: ""});
        evidence.sessionKeySignature = hex"01";
        evidence.sessionKey = sessionKey;
    }

    function _quoteReport(uint8 marker) private pure returns (TpmReport memory) {
        TpmQuoteReport memory quote = TpmQuoteReport({
            tpm2bAttest: abi.encodePacked("anvil-quote-", marker),
            tpmSignature: abi.encodePacked("anvil-quote-signature-", marker),
            pcrValues: new PcrValue[](0)
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmQuote,
            data: abi.encode(quote)
        });
    }

    function _certifyReport(uint8 marker) private pure returns (TpmReport memory) {
        TpmCertifyReport memory certify = TpmCertifyReport({
            tpm2bAttest: abi.encodePacked("anvil-certify-", marker),
            tpmSignature: abi.encodePacked("anvil-certify-signature-", marker),
            tpmtPublic: hex"0000000000040072"
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmCertify,
            data: abi.encode(certify)
        });
    }

    function _identity(uint8 typeId, uint8 marker) private pure returns (PublicIdentity memory identity) {
        bytes memory key = new bytes(65);
        key[0] = 0x04;
        key[64] = bytes1(marker);
        return PublicIdentity({typeId: typeId, key: key});
    }
}
