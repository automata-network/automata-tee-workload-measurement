// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {TpmQuoteVerificationResult, TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {Bytes48} from "../src/lib/LibBytes.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {PcrComparison} from "../src/lib/PcrComparison.sol";
import {MockTpmAttestation} from "./mocks/MockTpmAttestation.sol";
import {
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    PublicIdentity,
    TpmVerificationRequest
} from "../src/types/Common.sol";
import {
    PcrValue256,
    PcrValue384,
    TpmQuoteEvidence,
    TpmReport,
    TpmReportType,
    VerificationBackendType
} from "../src/types/Evidence.sol";
import {ALGO_ID_ES256} from "../src/types/Constants.sol";

contract TpmVerifierBanksHarness is TpmVerifier {
    constructor(ITpmAttestation attestation) TpmVerifier(attestation, IZkVerifierRegistry(address(0))) {}

    function verify(
        TpmReport memory report,
        PublicIdentity memory akPub,
        bytes32 qualifyingData,
        TpmVerificationRequest memory request
    ) external returns (TpmQuoteVerificationResult memory) {
        return verifyTpmQuote(report, akPub, qualifyingData, request);
    }

    function requestCommitment(TpmVerificationRequest memory request) external pure returns (bytes32) {
        return computeVerificationRequestCommitment(request);
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

    function testRawQuoteEvaluatesSha256AndSha384AndReturnsSignedPcrDigest() public {
        bytes memory signature = hex"010203040506";
        TpmReport memory report = _mixedBankReport(signature, false, PcrComparison.STATIC);
        TpmVerificationRequest memory request = _request(PcrComparison.STATIC);
        TpmQuoteVerificationResult memory result = verifier.verify(report, akPub, QUALIFYING_DATA, request);

        assertEq(result.akPubFingerprint, LibKey.computeKeyFingerprint(akPub));
        assertEq(result.qualifyingData, QUALIFYING_DATA);
        assertEq(result.tpmSignatureHash, keccak256(signature));
        assertEq(result.pcrDigest, sha256(abi.encodePacked(SHA256_PCR15, sha384Pcr15.first, sha384Pcr15.second)));
        assertEq(result.verificationRequestCommitment, verifier.requestCommitment(request));
    }

    function testRawQuoteRejectsSha384BeforeSha256() public {
        TpmReport memory report = _mixedBankReport(hex"01", true, PcrComparison.STATIC);
        vm.expectRevert(TpmVerifier.InvalidPcrBankOrder.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, _request(PcrComparison.STATIC));
    }

    function testRawQuoteRejectsDynamicSha384Policy() public {
        TpmReport memory report = _mixedBankReport(hex"01", false, PcrComparison.DYNAMIC_SUBSEQUENCE);
        vm.expectPartialRevert(TpmVerifier.TpmQuoteBackendDoesNotSatisfyPolicy.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, _request(PcrComparison.DYNAMIC_SUBSEQUENCE));
    }

    function testExtendFromZeroAndPublishedPcr15RulesBothPassAgainstOneQuotedValue() public {
        bytes32 extendValue = bytes32(uint256(0x1234));
        bytes32 measuredPcr15 = sha256(abi.encodePacked(bytes32(0), extendValue));
        TpmVerificationRequest memory request = _duplicatePcr15Request(measuredPcr15, extendValue);

        TpmQuoteVerificationResult memory result =
            verifier.verify(_sha256OnlyReport(measuredPcr15), akPub, QUALIFYING_DATA, request);
        assertEq(result.pcrDigest, sha256(abi.encodePacked(measuredPcr15)));
        assertEq(request.pcrs256.length, 2);
        assertEq(request.pcrs256[0].pcrIndex, 15);
        assertEq(request.pcrs256[1].pcrIndex, 15);

        request.pcrs256[0].comparison = PcrComparison.encodeStatic256(bytes32(uint256(0xdead)));
        TpmReport memory report = _sha256OnlyReport(measuredPcr15);
        vm.expectPartialRevert(TpmVerifier.PcrStaticMismatch256.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, request);

        request = _duplicatePcr15Request(measuredPcr15, bytes32(uint256(0x1235)));
        report = _sha256OnlyReport(measuredPcr15);
        vm.expectPartialRevert(TpmVerifier.PcrStaticMismatch256.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, request);
    }

    function testMissingQuotedPcr15FailsExactSelection() public {
        bytes32 measuredPcr15 = sha256(abi.encodePacked(bytes32(0), bytes32(uint256(0x1234))));
        TpmVerificationRequest memory request = _duplicatePcr15Request(measuredPcr15, bytes32(uint256(0x1234)));
        request.pcrs256[0].pcrIndex = 7;
        request.pcrs256[1].pcrIndex = 7;
        TpmReport memory report = _sha256OnlyReport(measuredPcr15);
        vm.expectPartialRevert(TpmVerifier.PcrSelectionMismatch.selector);
        verifier.verify(report, akPub, QUALIFYING_DATA, request);
    }

    function testVerificationRequestCommitmentMatchesRustAndPortalVector() public view {
        PcrSpec256[] memory rules256 = new PcrSpec256[](2);
        rules256[0] = PcrSpec256({
            pcrIndex: 1, comparison: PcrComparison.encodeStatic256(bytes32(uint256(type(uint256).max) / 0xff * 0x11))
        });
        rules256[1] = PcrSpec256({
            pcrIndex: 15,
            comparison: PcrComparison.encodeExtendFromZero256(bytes32(uint256(type(uint256).max) / 0xff * 0x22))
        });
        PcrSpec384[] memory rules384 = new PcrSpec384[](1);
        rules384[0] = PcrSpec384({
            pcrIndex: 15,
            comparison: PcrComparison.encodeExtendFromZero384(
                Bytes48({
                    first: bytes32(uint256(type(uint256).max) / 0xff * 0x33),
                    second: bytes16(uint128(type(uint128).max) / 0xff * 0x33)
                })
            )
        });
        TpmVerificationRequest memory request = TpmVerificationRequest({
            workloadId: bytes32(uint256(type(uint256).max) / 0xff * 0x01),
            baseImageId: bytes32(uint256(type(uint256).max) / 0xff * 0x02),
            platformProfileId: bytes32(uint256(type(uint256).max) / 0xff * 0x03),
            measurementVariantId: bytes32(uint256(type(uint256).max) / 0xff * 0x04),
            pcrBankSelection: PcrBankSelection.Sha256AndSha384,
            pcrs256: rules256,
            pcrs384: rules384
        });

        assertEq(
            verifier.requestCommitment(request), 0xc60feb45c97a8f69fbd1275315e2a2111daa1e1690089b315e0f5fe670b4a6ce
        );
    }

    function _sha256OnlyReport(bytes32 measuredPcr15) private view returns (TpmReport memory) {
        PcrValue256[] memory values256 = new PcrValue256[](1);
        values256[0] = PcrValue256({pcrIndex: 15, value: measuredPcr15, eventLogHashes: new bytes32[](0)});
        bytes32 pcrDigest = sha256(abi.encodePacked(measuredPcr15));
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
            bytes4(uint32(1)),
            bytes2(uint16(0x000b)),
            bytes1(uint8(3)),
            bytes3(0x008000),
            bytes2(uint16(32)),
            pcrDigest
        );
        TpmQuoteEvidence memory evidence = TpmQuoteEvidence({
            tpmsAttest: tpmsAttest,
            tpmSignature: hex"01",
            pcr0StartupLocality: 0xff,
            pcrValues256: values256,
            pcrValues384: new PcrValue384[](0)
        });
        return TpmReport({
            verificationBackendType: VerificationBackendType.Solidity,
            tpmReportType: TpmReportType.TpmQuote,
            data: abi.encode(evidence)
        });
    }

    function _duplicatePcr15Request(bytes32 measuredPcr15, bytes32 extendValue)
        private
        pure
        returns (TpmVerificationRequest memory request)
    {
        PcrSpec256[] memory rules = new PcrSpec256[](2);
        rules[0] = PcrSpec256({pcrIndex: 15, comparison: PcrComparison.encodeStatic256(measuredPcr15)});
        rules[1] = PcrSpec256({pcrIndex: 15, comparison: PcrComparison.encodeExtendFromZero256(extendValue)});
        return TpmVerificationRequest({
            workloadId: bytes32(uint256(1)),
            baseImageId: bytes32(uint256(2)),
            platformProfileId: bytes32(uint256(3)),
            measurementVariantId: bytes32(uint256(4)),
            pcrBankSelection: PcrBankSelection.Sha256,
            pcrs256: rules,
            pcrs384: new PcrSpec384[](0)
        });
    }

    function _mixedBankReport(bytes memory signature, bool reverseBanks, uint16 sha384ComparisonType)
        private
        view
        returns (TpmReport memory)
    {
        bytes32[] memory sha256Events = new bytes32[](0);
        Bytes48[] memory sha384Events = new Bytes48[](sha384ComparisonType == PcrComparison.STATIC ? 0 : 1);
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

    function _request(uint16 sha384ComparisonType) private view returns (TpmVerificationRequest memory request) {
        PcrSpec256[] memory rules256 = new PcrSpec256[](1);
        rules256[0] = PcrSpec256({pcrIndex: 15, comparison: PcrComparison.encodeStatic256(SHA256_PCR15)});

        Bytes48[] memory match384 = new Bytes48[](1);
        match384[0] = sha384Pcr15;
        PcrSpec384[] memory rules384 = new PcrSpec384[](1);
        rules384[0] = PcrSpec384({
            pcrIndex: 15,
            comparison: sha384ComparisonType == PcrComparison.STATIC
                ? PcrComparison.encodeStatic384(sha384Pcr15)
                : PcrComparison.encodeDynamic384(sha384ComparisonType, match384)
        });
        return TpmVerificationRequest({
            workloadId: bytes32(uint256(1)),
            baseImageId: bytes32(uint256(2)),
            platformProfileId: bytes32(uint256(3)),
            measurementVariantId: bytes32(uint256(4)),
            pcrBankSelection: PcrBankSelection.Sha256AndSha384,
            pcrs256: rules256,
            pcrs384: rules384
        });
    }
}
