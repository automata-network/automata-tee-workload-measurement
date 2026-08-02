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
}
