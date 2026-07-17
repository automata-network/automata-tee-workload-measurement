// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
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
    SESSION_NONCE_DOMAIN
} from "../src/types/Constants.sol";

/// @dev Transaction-path mock only. It authenticates no hardware evidence.
contract AnvilLifecycleTeeVerifier is ITeeVerifier {
    function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32) {
        return keccak256(teeReport.data);
    }

    function verifyTeeReport(TeeReport memory teeReport) external pure returns (TeeVerificationResult memory result) {
        return TeeVerificationResult({valid: true, reportData: "", teeType: teeReport.teeType});
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
    AnvilLifecycleTeeVerifier private teeVerifier;
    AnvilLifecycleTpmVerifier private tpmVerifier;
    AnvilLifecycleAkVerifier private akVerifier;
    SessionRegistry private sessionRegistry;

    PublicIdentity private ownerIdentity;

    function run() external {
        vm.startBroadcast();

        ownerIdentity = _identity(ALGO_ID_ES256K, 0x01);
        signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        teeVerifier = new AnvilLifecycleTeeVerifier();
        tpmVerifier = new AnvilLifecycleTpmVerifier();
        akVerifier = new AnvilLifecycleAkVerifier();
        sessionRegistry = new SessionRegistry(
            teeVerifier, tpmVerifier, signatureVerifier, akVerifier, baseImageRegistry, workloadRegistry
        );

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
