// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {
    AmdSnpSecurityPolicy,
    AmdSnpSecurityPolicyUpdate
} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {AmdSnpPolicy} from "../src/lib/AmdSnpPolicy.sol";

contract AmdSnpSecurityPolicyRegistryV2 is AmdSnpSecurityPolicyRegistry {
    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract AmdSnpSecurityPolicyRegistryTest is Test {
    address private constant OWNER = address(0x1234);
    address private constant NOT_OWNER = address(0x5678);
    uint24 private constant MILAN_CPUID = 0x190101;
    uint24 private constant GENOA_CPUID = 0x191101;
    bytes32 private constant MINIMUM_TCB = 0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004;
    bytes32 private constant PLATFORM_INFO_POLICY = 0x0000000000000000000000000000000000000000000000010000000000000020;
    bytes32 private constant SOURCE_DIGEST = keccak256("policy-source");

    AmdSnpSecurityPolicyRegistry private registry;

    function setUp() public {
        AmdSnpSecurityPolicyRegistry implementation = new AmdSnpSecurityPolicyRegistry();
        registry = AmdSnpSecurityPolicyRegistry(
            address(new ERC1967Proxy(address(implementation), abi.encodeCall(implementation.initialize, (OWNER))))
        );
    }

    function testRegisterReadAndUpdateSortedPolicies() public {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](2);
        updates[0] = _activeUpdate(MILAN_CPUID, 1);
        updates[1] = _activeUpdate(GENOA_CPUID, 1);

        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        AmdSnpSecurityPolicy memory policy = registry.getActivePolicy(GENOA_CPUID);
        assertEq(policy.minimumTcb, MINIMUM_TCB);
        assertEq(policy.platformInfoPolicy, PLATFORM_INFO_POLICY);
        assertEq(policy.sourceDigest, SOURCE_DIGEST);
        assertEq(policy.revision, 1);
        assertTrue(policy.active);
        assertEq(policy.requiredLaunchMitigationVector, 0);
        assertEq(policy.requiredCurrentMitigationVector, 0);
    }

    function testSameRevisionAndStateIsIdempotentAndKeepsSourceDigest() public {
        _register(GENOA_CPUID);
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(GENOA_CPUID, 1);

        vm.recordLogs();
        vm.prank(OWNER);
        registry.updatePolicies(updates, keccak256("new-file"));

        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(registry.getPolicy(GENOA_CPUID).sourceDigest, SOURCE_DIGEST);
    }

    function testRejectsUpdatePreparedAgainstStaleRevision() public {
        _register(GENOA_CPUID);
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(GENOA_CPUID, 2);

        vm.prank(OWNER);
        registry.updatePolicies(updates, keccak256("revision-2"));

        updates[0] = _activeUpdate(GENOA_CPUID, 3);
        updates[0].expectedRevision = 1;
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.PolicyRevisionMismatch.selector, GENOA_CPUID, 2, 1)
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, keccak256("stale-revision-3"));
    }

    function testDeactivatePreservesPolicyAndReactivateRequiresNewRevision() public {
        _register(GENOA_CPUID);
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 1, 2, false, bytes32(0), bytes32(0), 0, 0);

        vm.prank(OWNER);
        registry.updatePolicies(updates, keccak256("deactivate"));

        AmdSnpSecurityPolicy memory inactive = registry.getPolicy(GENOA_CPUID);
        assertFalse(inactive.active);
        assertEq(inactive.minimumTcb, MINIMUM_TCB);
        assertEq(inactive.platformInfoPolicy, PLATFORM_INFO_POLICY);
        vm.expectRevert(abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.PolicyNotActive.selector, GENOA_CPUID));
        registry.getActivePolicy(GENOA_CPUID);

        updates[0] = _activeUpdate(GENOA_CPUID, 3);
        vm.prank(OWNER);
        registry.updatePolicies(updates, keccak256("reactivate"));
        assertTrue(registry.getActivePolicy(GENOA_CPUID).active);
    }

    function testRejectsInvalidBatchesAndRevisions() public {
        AmdSnpSecurityPolicyUpdate[] memory empty = new AmdSnpSecurityPolicyUpdate[](0);
        vm.expectRevert(AmdSnpSecurityPolicyRegistry.EmptyPolicyUpdate.selector);
        vm.prank(OWNER);
        registry.updatePolicies(empty, SOURCE_DIGEST);

        AmdSnpSecurityPolicyUpdate[] memory one = new AmdSnpSecurityPolicyUpdate[](1);
        one[0] = _activeUpdate(GENOA_CPUID, 1);
        vm.expectRevert(AmdSnpSecurityPolicyRegistry.InvalidSourceDigest.selector);
        vm.prank(OWNER);
        registry.updatePolicies(one, bytes32(0));

        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](2);
        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[1] = _activeUpdate(MILAN_CPUID, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.PolicyUpdatesNotSorted.selector, GENOA_CPUID, MILAN_CPUID
            )
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        _register(GENOA_CPUID);
        updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[0].minimumTcb = bytes32(uint256(MINIMUM_TCB) + 1);
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.PolicyRevisionConflict.selector, GENOA_CPUID, 1)
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = _activeUpdate(GENOA_CPUID, 0);
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.InvalidPolicyRevision.selector, GENOA_CPUID, 0, 2)
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 1, 2, false, bytes32(0), bytes32(0), 1, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.InvalidInactivePolicy.selector,
                GENOA_CPUID,
                bytes32(0),
                bytes32(0),
                uint64(1),
                uint64(0)
            )
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);
    }

    function testRejectsUnsupportedCpuidAndMalformedPolicy() public {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(0x1a0101, 1);
        vm.expectRevert(abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.UnsupportedCpuid.selector, 0x1a0101));
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[0].minimumTcb = bytes32(uint256(1) << 32);
        vm.expectRevert(abi.encodeWithSelector(AmdSnpPolicy.InvalidAmdSnpTcbValue.selector, updates[0].minimumTcb));
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[0].platformInfoPolicy = bytes32(uint256(1) | (uint256(1) << 64));
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpPolicy.InvalidAmdSnpPlatformInfoPolicy.selector, updates[0].platformInfoPolicy)
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[0].platformInfoPolicy = bytes32(uint256(1) << 6);
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpPolicy.InvalidAmdSnpPlatformInfoPolicy.selector, updates[0].platformInfoPolicy)
        );
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 0, 1, false, bytes32(0), bytes32(0), 0, 0);
        vm.expectRevert(abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.PolicyNotFound.selector, GENOA_CPUID));
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);
    }

    function testPackedTcbHelpersCompareEachComponent() public pure {
        bytes32 lower = bytes32(uint256(MINIMUM_TCB) - 1);
        assertTrue(AmdSnpPolicy.tcbMeetsMinimum(MINIMUM_TCB, lower));
        assertFalse(AmdSnpPolicy.tcbMeetsMinimum(lower, MINIMUM_TCB));

        // A single lagging component is enough to fail, even when every other lane is ahead.
        bytes32 mixed = bytes32(uint256(MINIMUM_TCB) | (uint256(0xff) << 200));
        assertFalse(AmdSnpPolicy.tcbMeetsMinimum(lower, mixed));
    }

    function testPackedTcbComparisonRejectsReservedComponents() public pure {
        bytes32 invalidActual = bytes32(uint256(1) << 32);
        bytes32 invalidMinimum = bytes32(uint256(1) << 32);
        assertFalse(AmdSnpPolicy.tcbMeetsMinimum(invalidActual, bytes32(0)));
        assertFalse(AmdSnpPolicy.tcbMeetsMinimum(bytes32(0), invalidMinimum));
    }

    function testPlatformInfoMergeUnionsBothSidesAndFlagsConflicts() public pure {
        // Left requires bit 0 set; right requires bit 1 set. The union requires both.
        (bool ok, bytes32 merged) = AmdSnpPolicy.tryMergePlatformInfoPolicies(bytes32(uint256(1)), bytes32(uint256(2)));
        assertTrue(ok);
        assertEq(merged, bytes32(uint256(3)));

        // Left requires bit 0 set; right requires bit 0 cleared.
        (bool conflicting,) = AmdSnpPolicy.tryMergePlatformInfoPolicies(bytes32(uint256(1)), bytes32(uint256(1) << 64));
        assertFalse(conflicting);
    }

    function testPlatformInfoHelpersRejectMalformedPolicies() public pure {
        bytes32 highReservedBit = bytes32(uint256(1) << 128);
        bytes32 overlapping = bytes32(uint256(1) | (uint256(1) << 64));
        (bool highBitOk,) = AmdSnpPolicy.tryMergePlatformInfoPolicies(highReservedBit, bytes32(0));
        (bool overlappingOk,) = AmdSnpPolicy.tryMergePlatformInfoPolicies(overlapping, bytes32(0));
        assertFalse(highBitOk);
        assertFalse(overlappingOk);
        assertFalse(AmdSnpPolicy.platformInfoMatches(0, highReservedBit));
        assertFalse(AmdSnpPolicy.platformInfoMatches(1, overlapping));
    }

    function testSupportedCpuidWindow() public pure {
        assertTrue(AmdSnpPolicy.isSupportedCpuid(0x190000)); // Milan
        assertTrue(AmdSnpPolicy.isSupportedCpuid(0x191002)); // Genoa, nonzero stepping
        assertFalse(AmdSnpPolicy.isSupportedCpuid(0x192000)); // model above 0x1f
        assertFalse(AmdSnpPolicy.isSupportedCpuid(0x1a0000)); // Turin
    }

    function testOnlyOwnerMayUpdateOrUpgradeAndStorageSurvivesUpgrade() public {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        vm.expectRevert();
        vm.prank(NOT_OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        _register(GENOA_CPUID);
        AmdSnpSecurityPolicyRegistryV2 next = new AmdSnpSecurityPolicyRegistryV2();
        vm.prank(OWNER);
        registry.upgradeToAndCall(address(next), "");

        assertEq(AmdSnpSecurityPolicyRegistryV2(address(registry)).implementationVersion(), 2);
        assertEq(registry.getActivePolicy(GENOA_CPUID).minimumTcb, MINIMUM_TCB);
    }

    /// @dev A deactivation must supply zeros and keeps the previous values in storage for audit
    ///      history, so the event has to report what the update applied, not what storage holds.
    function testDeactivationEventReportsTheAppliedZeros() public {
        _register(GENOA_CPUID);

        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 1, 2, false, bytes32(0), bytes32(0), 0, 0);

        vm.recordLogs();
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        (
            uint64 revision,
            bool active,
            bytes32 minimumTcb,
            bytes32 platformInfoPolicy,
            uint64 requiredLaunch,
            uint64 requiredCurrent
        ) = abi.decode(logs[0].data, (uint64, bool, bytes32, bytes32, uint64, uint64));

        assertEq(revision, 2);
        assertFalse(active);
        assertEq(minimumTcb, bytes32(0));
        assertEq(platformInfoPolicy, bytes32(0));
        assertEq(requiredLaunch, 0);
        assertEq(requiredCurrent, 0);

        // Storage still carries the pre-deactivation values for audit history.
        assertEq(registry.getPolicy(GENOA_CPUID).minimumTcb, MINIMUM_TCB);
    }

    function _register(uint24 cpuid) private {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(cpuid, 1);
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);
    }

    function _activeUpdate(uint24 cpuid, uint64 revision) private pure returns (AmdSnpSecurityPolicyUpdate memory) {
        uint64 expectedRevision = revision == 0 ? 1 : revision - 1;
        return
            AmdSnpSecurityPolicyUpdate(cpuid, expectedRevision, revision, true, MINIMUM_TCB, PLATFORM_INFO_POLICY, 0, 0);
    }
}
