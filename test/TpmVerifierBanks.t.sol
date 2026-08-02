// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {TpmQuoteVerificationResult, TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {Bytes48} from "../src/lib/LibBytes.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {MockTpmAttestation} from "./mocks/MockTpmAttestation.sol";
import {
    PcrBankSelection,
    PcrBinding256,
    PcrBinding384,
    PcrSetEntry256,
    PcrSetEntry384,
    PcrSpec256,
    PcrSpec384,
    PcrVerifyType,
    ProviderPcrRequirements,
    PublicIdentity,
    ResolvedPcrPolicy
} from "../src/types/Common.sol";
import {
    PcrValue256,
    PcrValue384,
    TpmQuoteEvidence,
    TpmReport,
    TpmReportType,
    VerificationBackendType
} from "../src/types/Evidence.sol";
import {
    ALGO_ID_ES256,
    PCR_SET_SHA256_COMMITMENT_DOMAIN,
    PCR_SET_SHA384_COMMITMENT_DOMAIN
} from "../src/types/Constants.sol";

contract TpmVerifierBanksHarness is TpmVerifier {
    constructor(ITpmAttestation attestation) TpmVerifier(attestation, IZkVerifierRegistry(address(0))) {}

    function verify(
        TpmReport memory report,
        PublicIdentity memory akPub,
        bytes32 qualifyingData,
        ResolvedPcrPolicy memory policy,
        ProviderPcrRequirements memory requirements
    ) external returns (TpmQuoteVerificationResult memory) {
        return verifyTpmQuote(report, akPub, qualifyingData, policy, requirements);
    }

    function policyCommitments(ResolvedPcrPolicy memory policy) external pure returns (bytes32, bytes32) {
        return (computeSha256PolicyCommitment(policy), computeSha384PolicyCommitment(policy));
    }

    function bindingCommitments(ProviderPcrRequirements memory requirements) external pure returns (bytes32, bytes32) {
        return (computeSha256PcrBindingCommitment(requirements), computeSha384PcrBindingCommitment(requirements));
    }
}

contract TpmVerifierBanksTest is Test {
    bytes32 internal constant QUALIFYING_DATA = keccak256("qualifying-data");
    bytes32 internal constant SHA256_PCR15 = keccak256("sha256-pcr15");

    TpmVerifierBanksHarness internal verifier;
    PublicIdentity internal akPub;
    Bytes48 internal sha384Pcr15;

    function setUp() public {
        verifier = new TpmVerifierBanksHarness(new MockTpmAttestation());
        akPub = PublicIdentity({typeId: ALGO_ID_ES256, key: abi.encodePacked(bytes1(0x04), new bytes(64))});
        sha384Pcr15 = Bytes48({first: keccak256("sha384-pcr15-first"), second: bytes16(keccak256("second"))});
    }

    function testRawQuoteEvaluatesSha256AndSha384AndReturnsAllCommitments() public {
        bytes memory signature = hex"010203040506";
        TpmReport memory report = _mixedBankReport(signature, false, PcrVerifyType.STATIC);
        ResolvedPcrPolicy memory policy = _policy(PcrVerifyType.STATIC);
        ProviderPcrRequirements memory requirements = _emptyRequirements();

        TpmQuoteVerificationResult memory result = verifier.verify(report, akPub, QUALIFYING_DATA, policy, requirements);
        (bytes32 expectedPolicy256, bytes32 expectedPolicy384) = verifier.policyCommitments(policy);
        (bytes32 expectedBinding256, bytes32 expectedBinding384) = verifier.bindingCommitments(requirements);

        PcrSetEntry256[] memory entries256 = new PcrSetEntry256[](1);
        entries256[0] = PcrSetEntry256({pcrIndex: 15, value: SHA256_PCR15});
        PcrSetEntry384[] memory entries384 = new PcrSetEntry384[](1);
        entries384[0] = PcrSetEntry384({pcrIndex: 15, value: sha384Pcr15});

        assertEq(result.akPubFingerprint, LibKey.computeKeyFingerprint(akPub));
        assertEq(result.qualifyingData, QUALIFYING_DATA);
        assertEq(result.tpmSignatureHash, keccak256(signature));
        assertEq(result.sha256PolicyCommitment, expectedPolicy256);
        assertEq(result.sha384PolicyCommitment, expectedPolicy384);
        assertEq(result.sha256PcrBindingCommitment, expectedBinding256);
        assertEq(result.sha384PcrBindingCommitment, expectedBinding384);
        assertEq(result.sha256PcrSetCommitment, keccak256(abi.encode(PCR_SET_SHA256_COMMITMENT_DOMAIN, entries256)));
        assertEq(result.sha384PcrSetCommitment, keccak256(abi.encode(PCR_SET_SHA384_COMMITMENT_DOMAIN, entries384)));
    }

    function testRawQuoteRejectsSha384BeforeSha256() public {
        TpmReport memory report = _mixedBankReport(hex"01", true, PcrVerifyType.STATIC);
        vm.expectRevert(TpmVerifier.InvalidPcrBankOrder.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, _policy(PcrVerifyType.STATIC), _emptyRequirements());
    }

    function testRawQuoteRejectsDynamicSha384Policy() public {
        TpmReport memory report = _mixedBankReport(hex"01", false, PcrVerifyType.DYNAMIC_SUBSEQUENCE);
        vm.expectPartialRevert(TpmVerifier.TpmQuoteBackendDoesNotSatisfyPolicy.selector);
        verifier.verify(
            report, akPub, QUALIFYING_DATA, _policy(PcrVerifyType.DYNAMIC_SUBSEQUENCE), _emptyRequirements()
        );
    }

    function _mixedBankReport(bytes memory signature, bool reverseBanks, PcrVerifyType sha384VerifyType)
        private
        view
        returns (TpmReport memory)
    {
        bytes32[] memory sha256Events = new bytes32[](0);
        Bytes48[] memory sha384Events = new Bytes48[](sha384VerifyType == PcrVerifyType.STATIC ? 0 : 1);
        if (sha384Events.length == 1) sha384Events[0] = sha384Pcr15;

        PcrValue256[] memory values256 = new PcrValue256[](1);
        values256[0] = PcrValue256({pcrIndex: 15, value: SHA256_PCR15, eventLogHashes: sha256Events});
        PcrValue384[] memory values384 = new PcrValue384[](1);
        values384[0] = PcrValue384({pcrIndex: 15, value: sha384Pcr15, eventLogHashes: sha384Events});

        bytes32 pcrDigest = sha256(abi.encodePacked(SHA256_PCR15, sha384Pcr15.first, sha384Pcr15.second));
        bytes memory sha256Selection = abi.encodePacked(bytes2(uint16(0x000b)), bytes1(uint8(3)), bytes3(0x008000));
        bytes memory sha384Selection = abi.encodePacked(bytes2(uint16(0x000c)), bytes1(uint8(3)), bytes3(0x008000));
        bytes memory selections = reverseBanks
            ? bytes.concat(sha384Selection, sha256Selection)
            : bytes.concat(sha256Selection, sha384Selection);
        bytes memory tpmsAttest = abi.encodePacked(
            bytes4(uint32(0xff544347)),
            bytes2(uint16(0x8018)),
            bytes2(0),
            bytes2(uint16(32)),
            QUALIFYING_DATA,
            bytes8(0),
            bytes4(0),
            bytes4(0),
            bytes1(0),
            bytes8(0),
            bytes4(uint32(2)),
            selections,
            bytes2(uint16(32)),
            pcrDigest
        );
        TpmQuoteEvidence memory evidence = TpmQuoteEvidence({
            tpmsAttest: tpmsAttest,
            tpmSignature: signature,
            pcr0StartupLocality: 0xff,
            pcrValues256: values256,
            pcrValues384: values384
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmQuote,
            data: abi.encode(evidence)
        });
    }

    function _policy(PcrVerifyType sha384VerifyType) private view returns (ResolvedPcrPolicy memory policy) {
        bytes32[] memory match256 = new bytes32[](1);
        match256[0] = SHA256_PCR15;
        PcrSpec256[] memory rules256 = new PcrSpec256[](1);
        rules256[0] = PcrSpec256({pcrIndex: 15, verifyType: PcrVerifyType.STATIC, matchData: match256});

        Bytes48[] memory match384 = new Bytes48[](1);
        match384[0] = sha384Pcr15;
        PcrSpec384[] memory rules384 = new PcrSpec384[](1);
        rules384[0] = PcrSpec384({pcrIndex: 15, verifyType: sha384VerifyType, matchData: match384});
        return ResolvedPcrPolicy({
            workloadId: bytes32(uint256(1)),
            baseImageId: bytes32(uint256(2)),
            platformProfileId: bytes32(uint256(3)),
            measurementVariantId: bytes32(uint256(4)),
            pcrBankSelection: PcrBankSelection.Sha256AndSha384,
            invariants256: rules256,
            variantPcrs256: new PcrSpec256[](0),
            workloadPcrs256: new PcrSpec256[](0),
            invariants384: rules384,
            variantPcrs384: new PcrSpec384[](0),
            workloadPcrs384: new PcrSpec384[](0)
        });
    }

    function _emptyRequirements() private pure returns (ProviderPcrRequirements memory requirements) {
        return ProviderPcrRequirements({
            pcrBindings256: new PcrBinding256[](0),
            pcrJoinIndexes256: new uint8[](0),
            pcrBindings384: new PcrBinding384[](0),
            pcrJoinIndexes384: new uint8[](0)
        });
    }
}
