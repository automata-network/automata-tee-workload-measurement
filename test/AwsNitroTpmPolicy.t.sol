// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {SessionRegistry} from "../src/SessionRegistry.sol";
import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {Bytes48, LibBytes} from "../src/lib/LibBytes.sol";
import {PcrComparison} from "../src/lib/PcrComparison.sol";
import {
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    ResolvedPcrPolicy,
    TpmVerificationRequest
} from "../src/types/Common.sol";

contract SessionRegistryAwsHarness is SessionRegistry {
    constructor()
        SessionRegistry(
            ITeeVerifier(address(1)),
            TpmVerifier(address(2)),
            ISignatureVerifier(address(4)),
            IAkCollateralVerifier(address(5)),
            IBaseImageRegistry(address(6)),
            IWorkloadRegistry(address(7)),
            IAmdSnpSecurityPolicyRegistry(address(8))
        )
    {}

    function verifyAwsDocumentFreshness(uint64 documentTimestampSeconds) external view {
        _verifyAwsDocumentFreshness(documentTimestampSeconds);
    }

    function gcpProviderPcrRules(bytes32 extendValue)
        external
        pure
        returns (PcrSpec256[] memory pcrs256, PcrSpec384[] memory pcrs384)
    {
        GeneratedProviderPcrRules memory rules = _gcpProviderPcrRules(extendValue);
        return (rules.pcrs256, rules.pcrs384);
    }

    function awsProviderPcrRules(bytes32 reportId, PcrBankSelection bankSelection)
        external
        pure
        returns (PcrSpec256[] memory pcrs256, PcrSpec384[] memory pcrs384)
    {
        GeneratedProviderPcrRules memory rules = _awsProviderPcrRules(reportId, bankSelection);
        return (rules.pcrs256, rules.pcrs384);
    }

    function buildTpmVerificationRequest(
        ResolvedPcrPolicy memory policy,
        PcrSpec256[] memory providerPcrs256,
        PcrSpec384[] memory providerPcrs384
    ) external pure returns (TpmVerificationRequest memory) {
        return _buildTpmVerificationRequest(
            policy, GeneratedProviderPcrRules({pcrs256: providerPcrs256, pcrs384: providerPcrs384})
        );
    }
}

contract AwsNitroTpmPolicyTest is Test {
    address internal constant OWNER = address(0xa11ce);
    address internal constant OTHER = address(0xb0b);

    SessionRegistryAwsHarness internal registry;

    function setUp() public {
        registry = SessionRegistryAwsHarness(
            address(
                new ERC1967Proxy(
                    address(new SessionRegistryAwsHarness()), abi.encodeCall(SessionRegistry.initialize, (OWNER))
                )
            )
        );
        vm.warp(1_800_000_000);
    }

    function testAwsRootTrustRejectsZeroAndRequiresOwner() public {
        vm.expectRevert(SessionRegistry.ZeroAwsNitroRootCertificateHash.selector);
        vm.prank(OWNER);
        registry.setAwsNitroRootCertificateTrust(bytes32(0), true);

        bytes32 rootHash = keccak256("aws-nitrotpm-root");
        vm.expectRevert();
        vm.prank(OTHER);
        registry.setAwsNitroRootCertificateTrust(rootHash, true);

        vm.prank(OWNER);
        registry.setAwsNitroRootCertificateTrust(rootHash, true);
        assertTrue(registry.trustedAwsNitroRootCertHashes(rootHash));

        vm.prank(OWNER);
        registry.setAwsNitroRootCertificateTrust(rootHash, false);
        assertFalse(registry.trustedAwsNitroRootCertHashes(rootHash));
    }

    function testAwsDocumentFreshnessUsesConfiguredInclusiveBoundaries() public {
        assertEq(registry.awsDocumentMaximumAgeSeconds(), 3600);
        assertEq(registry.awsDocumentAllowedFutureClockDifferenceSeconds(), 300);
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp - 3600));
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp + 300));

        vm.expectPartialRevert(SessionRegistry.AwsDocumentTooOld.selector);
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp - 3601));
        vm.expectPartialRevert(SessionRegistry.AwsDocumentTimestampInFuture.selector);
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp + 301));

        vm.startPrank(OWNER);
        registry.setAwsDocumentMaximumAgeSeconds(60);
        registry.setAwsDocumentAllowedFutureClockDifferenceSeconds(10);
        vm.stopPrank();
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp - 60));
        registry.verifyAwsDocumentFreshness(uint64(block.timestamp + 10));

        vm.expectRevert();
        vm.prank(OTHER);
        registry.setAwsDocumentMaximumAgeSeconds(120);
    }

    function testGcpProviderRuleUsesExactSha256ExtendValue() public view {
        bytes32 extendValue = bytes32(uint256(0x1234));
        (PcrSpec256[] memory pcrs256, PcrSpec384[] memory pcrs384) = registry.gcpProviderPcrRules(extendValue);

        assertEq(pcrs256.length, 1);
        assertEq(pcrs256[0].pcrIndex, 15);
        assertEq(pcrs256[0].comparison, abi.encode(uint16(PcrComparison.EXTEND_FROM_ZERO), extendValue));
        assertEq(pcrs384.length, 0);
    }

    function testAwsProviderRulesUseExactReportIdAndBankPadding() public view {
        bytes32 reportId = bytes32(uint256(0x5678));
        (PcrSpec256[] memory sha384Only256, PcrSpec384[] memory sha384Only384) =
            registry.awsProviderPcrRules(reportId, PcrBankSelection.Sha384);
        assertEq(sha384Only256.length, 0);
        assertEq(sha384Only384.length, 1);
        assertEq(sha384Only384[0].pcrIndex, 15);
        Bytes48 memory paddedReportId = LibBytes.toBytes48(abi.encodePacked(bytes16(0), reportId));
        assertEq(sha384Only384[0].comparison, abi.encode(uint16(PcrComparison.EXTEND_FROM_ZERO), paddedReportId));

        (PcrSpec256[] memory dual256, PcrSpec384[] memory dual384) =
            registry.awsProviderPcrRules(reportId, PcrBankSelection.Sha256AndSha384);
        assertEq(dual256.length, 1);
        assertEq(dual256[0].pcrIndex, 15);
        assertEq(dual256[0].comparison, abi.encode(uint16(PcrComparison.EXTEND_FROM_ZERO), reportId));
        assertEq(dual384.length, 1);
        assertEq(dual384[0].comparison, sha384Only384[0].comparison);
    }

    function testProviderPcr15AppendsWithoutOverwritingPublishedPcr15() public view {
        bytes memory publishedComparison = abi.encode(uint16(PcrComparison.STATIC), bytes32(uint256(1)));
        bytes memory providerComparison = abi.encode(uint16(PcrComparison.EXTEND_FROM_ZERO), bytes32(uint256(2)));
        PcrSpec256[] memory invariantPcrs256 = new PcrSpec256[](1);
        invariantPcrs256[0] = PcrSpec256({pcrIndex: 15, comparison: publishedComparison});
        PcrSpec256[] memory providerPcrs256 = new PcrSpec256[](1);
        providerPcrs256[0] = PcrSpec256({pcrIndex: 15, comparison: providerComparison});

        TpmVerificationRequest memory request = registry.buildTpmVerificationRequest(
            ResolvedPcrPolicy({
                workloadId: bytes32(uint256(1)),
                baseImageId: bytes32(uint256(2)),
                platformProfileId: bytes32(uint256(3)),
                measurementVariantId: bytes32(uint256(4)),
                pcrBankSelection: PcrBankSelection.Sha256,
                invariantPcrs256: invariantPcrs256,
                variantPcrs256: new PcrSpec256[](0),
                workloadPcrs256: new PcrSpec256[](0),
                invariantPcrs384: new PcrSpec384[](0),
                variantPcrs384: new PcrSpec384[](0),
                workloadPcrs384: new PcrSpec384[](0)
            }),
            providerPcrs256,
            new PcrSpec384[](0)
        );

        assertEq(request.pcrs256.length, 2);
        assertEq(request.pcrs256[0].pcrIndex, 15);
        assertEq(request.pcrs256[0].comparison, publishedComparison);
        assertEq(request.pcrs256[1].pcrIndex, 15);
        assertEq(request.pcrs256[1].comparison, providerComparison);
    }
}
