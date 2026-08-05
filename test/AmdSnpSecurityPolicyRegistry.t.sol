// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {
    AmdSnpSecurityPolicy,
    AmdSnpSecurityPolicyUpdate,
    VerifiedTeePolicyInputs
} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {AmdSnpPolicy} from "../src/lib/AmdSnpPolicy.sol";
import {Attribute, AttributeRequirement} from "../src/types/Common.sol";
import {TEEType} from "../src/types/Evidence.sol";
import {
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
    TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
    TDX_TCB_STATUS_OK,
    TEE_ATTRIBUTE_TRUE
} from "../src/types/Constants.sol";

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

    function testVerifyAmdSnpMitigationVectorsRequireVersionFiveAndAllRequiredBits() public {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(GENOA_CPUID, 1);
        updates[0].requiredLaunchMitigationVector = 0x03;
        updates[0].requiredCurrentMitigationVector = 0x05;
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        VerifiedTeePolicyInputs memory inputs = _validInputs();
        Attribute[] memory attributes = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpMitigationPolicyRequiresReportVersion.selector, uint32(3), uint32(5)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpReportVersion = 6;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpMitigationPolicyRequiresReportVersion.selector, uint32(6), uint32(5)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpReportVersion = 5;
        inputs.amdSevSnpLaunchMitigationVector = 0x07;
        inputs.amdSevSnpCurrentMitigationVector = 0x0d;
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x02;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpLaunchMitigationVectorMissing.selector, uint64(0x03), uint64(0x02)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x03;
        inputs.amdSevSnpCurrentMitigationVector = 0x04;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpCurrentMitigationVectorMissing.selector, uint64(0x05), uint64(0x04)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);
    }

    function testReviewedMilanPolicyRejectsPreviousAwsMitigationVectors() public {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(MILAN_CPUID, 1);
        updates[0].requiredLaunchMitigationVector = 0x16;
        updates[0].requiredCurrentMitigationVector = 0x16;
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);

        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpCpuid = MILAN_CPUID;
        inputs.amdSevSnpReportVersion = 5;
        inputs.amdSevSnpLaunchMitigationVector = 0x0f;
        inputs.amdSevSnpCurrentMitigationVector = 0x0f;
        Attribute[] memory attributes = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](0);

        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpLaunchMitigationVectorMissing.selector, uint64(0x16), uint64(0x0f)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x16;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.SnpCurrentMitigationVectorMissing.selector, uint64(0x16), uint64(0x0f)
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpCurrentMitigationVector = 0x16;
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);
    }

    function testZeroMitigationMasksAcceptVersionThreeReport() public {
        _register(GENOA_CPUID);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        assertEq(inputs.amdSevSnpReportVersion, 3);

        Attribute[] memory attributes = new Attribute[](0);
        registry.verifyTeePolicy(inputs, attributes, attributes, new AttributeRequirement[](0));
    }

    function testVerifyAmdSnpPolicyUsesRegistryDefaultsWhenBothSidesAreMissing() public {
        _register(GENOA_CPUID);
        Attribute[] memory attributes = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](0);
        VerifiedTeePolicyInputs memory inputs = _validInputs();

        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpTcbValues = bytes32(uint256(MINIMUM_TCB) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                inputs.amdSevSnpTcbValues
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x21;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                PLATFORM_INFO_POLICY,
                bytes32(uint256(0x21))
            )
        );
        registry.verifyTeePolicy(inputs, attributes, attributes, requirements);
    }

    function testVerifyAmdSnpTcbPolicyAppliesVariantOverrideAndAllowsCoordinatedRelaxation() public {
        _register(GENOA_CPUID);
        bytes32 lowerTcb = bytes32(uint256(MINIMUM_TCB) - 1);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpTcbValues = lowerTcb;

        Attribute[] memory profileAttributes = new Attribute[](1);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, bytes32(uint256(MINIMUM_TCB) + 1));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, lowerTcb);
        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = lowerTcb;
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues);

        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        variantAttributes = new Attribute[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                bytes32(uint256(MINIMUM_TCB) + 1),
                lowerTcb
            )
        );
        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
    }

    function testVerifyAmdSnpTcbPolicyRejectsOneSidedRelaxation() public {
        _register(GENOA_CPUID);
        bytes32 lowerTcb = bytes32(uint256(MINIMUM_TCB) - 1);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpTcbValues = lowerTcb;

        Attribute[] memory lowerBase = new Attribute[](1);
        lowerBase[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, lowerTcb);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                lowerTcb
            )
        );
        registry.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), new AttributeRequirement[](0));

        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = lowerTcb;
        AttributeRequirement[] memory lowerWorkload = new AttributeRequirement[](1);
        lowerWorkload[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                lowerTcb
            )
        );
        registry.verifyTeePolicy(inputs, new Attribute[](0), new Attribute[](0), lowerWorkload);
    }

    function testVerifyIntelTdxTcbPolicyAppliesVariantOverride() public view {
        uint256 configurationNeeded = uint256(1) << 3;
        VerifiedTeePolicyInputs memory inputs = VerifiedTeePolicyInputs({
            teeType: TEEType.IntelTDX,
            enabledTeeAttributes: 0,
            intelTdxTcbStatusBit: configurationNeeded,
            amdSevSnpTcbValues: bytes32(0),
            amdSevSnpPlatformInfo: 0,
            amdSevSnpCpuid: 0,
            amdSevSnpReportVersion: 0,
            amdSevSnpLaunchMitigationVector: 0,
            amdSevSnpCurrentMitigationVector: 0
        });
        Attribute[] memory profileAttributes = new Attribute[](1);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] =
            Attribute(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK | configurationNeeded));
        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = bytes32(TDX_TCB_STATUS_OK | configurationNeeded);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, allowedValues);

        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
    }

    function testVerifyAmdSnpPlatformInfoPolicyAppliesWholeVariantOverride() public {
        _register(GENOA_CPUID);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x30;
        Attribute[] memory profileAttributes = new Attribute[](1);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1) << 68));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1) << 4));

        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, new AttributeRequirement[](0));

        bytes32 effectiveProfilePolicy = bytes32(uint256(1) << 68);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                effectiveProfilePolicy,
                bytes32(uint256(0x30))
            )
        );
        registry.verifyTeePolicy(inputs, profileAttributes, new Attribute[](0), new AttributeRequirement[](0));
    }

    function testVerifyAmdSnpPolicyEnforcesWorkloadMinimumAndPlatformConflicts() public {
        _register(GENOA_CPUID);
        Attribute[] memory attributes = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = bytes32(uint256(MINIMUM_TCB) + 1);
        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues);

        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB
            )
        );
        registry.verifyTeePolicy(_validInputs(), attributes, attributes, requirements);

        attributes = new Attribute[](1);
        attributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1)));
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x21;
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributePolicyConflict.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                bytes32(uint256(1)),
                PLATFORM_INFO_POLICY
            )
        );
        registry.verifyTeePolicy(inputs, attributes, new Attribute[](0), new AttributeRequirement[](0));
    }

    function testVerifyAmdSnpPlatformInfoPolicyAllowsCoordinatedRelaxationAndRejectsOneSidedRelaxation() public {
        _register(GENOA_CPUID);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0;

        Attribute[] memory lowerBase = new Attribute[](1);
        lowerBase[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(0));
        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = bytes32(0);
        AttributeRequirement[] memory lowerWorkload = new AttributeRequirement[](1);
        lowerWorkload[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, allowedValues);

        registry.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), lowerWorkload);

        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                bytes32(0)
            )
        );
        registry.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), new AttributeRequirement[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                PLATFORM_INFO_POLICY,
                bytes32(0)
            )
        );
        registry.verifyTeePolicy(inputs, new Attribute[](0), new Attribute[](0), lowerWorkload);
    }

    function testVerifyAmdSnpBooleanAndGenericAttributes() public {
        _register(GENOA_CPUID);
        bytes32 customKey = keccak256("example.environment");
        Attribute[] memory profileAttributes = new Attribute[](2);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_TRUE);
        profileAttributes[1] = Attribute(customKey, bytes32(uint256(1)));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] = Attribute(customKey, bytes32(uint256(2)));
        AttributeRequirement[] memory requirements = new AttributeRequirement[](3);
        bytes32[] memory debugValues = new bytes32[](2);
        debugValues[1] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, debugValues);
        bytes32[] memory customValues = new bytes32[](1);
        customValues[0] = bytes32(uint256(2));
        requirements[1] = AttributeRequirement(customKey, customValues);
        bytes32[] memory nonSelectedValues = new bytes32[](1);
        nonSelectedValues[0] = TEE_ATTRIBUTE_TRUE;
        requirements[2] = AttributeRequirement(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, nonSelectedValues);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.enabledTeeAttributes = TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT;

        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        customValues[0] = bytes32(uint256(1));
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.AttributeValueNotAllowed.selector, customKey, bytes32(uint256(2))
            )
        );
        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        requirements[1].key = keccak256("example.missing");
        vm.expectRevert(
            abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.AttributeNotFound.selector, requirements[1].key)
        );
        registry.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
    }

    function testVerifyAmdSnpTcbPolicyMatrix() public {
        _register(GENOA_CPUID);
        bytes32 strongerTcb = bytes32(uint256(MINIMUM_TCB) + 1);

        for (uint256 actualMode = 0; actualMode < 2; actualMode++) {
            for (uint256 baseMode = 0; baseMode < 3; baseMode++) {
                for (uint256 workloadMode = 0; workloadMode < 3; workloadMode++) {
                    VerifiedTeePolicyInputs memory inputs = _validInputs();
                    inputs.amdSevSnpTcbValues = actualMode == 0 ? MINIMUM_TCB : strongerTcb;
                    Attribute[] memory attributes = new Attribute[](baseMode == 0 ? 0 : 1);
                    if (baseMode != 0) {
                        attributes[0] =
                            Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, baseMode == 1 ? MINIMUM_TCB : strongerTcb);
                    }
                    AttributeRequirement[] memory requirements = new AttributeRequirement[](workloadMode == 0 ? 0 : 1);
                    if (workloadMode != 0) {
                        bytes32[] memory values = new bytes32[](1);
                        values[0] = workloadMode == 1 ? MINIMUM_TCB : strongerTcb;
                        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, values);
                    }

                    bool basePermits = actualMode == 1 || baseMode != 2;
                    bool workloadPermits = actualMode == 1 || workloadMode != 2;
                    if (!basePermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                                strongerTcb,
                                MINIMUM_TCB
                            )
                        );
                    } else if (!workloadPermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                                MINIMUM_TCB
                            )
                        );
                    }
                    registry.verifyTeePolicy(inputs, attributes, new Attribute[](0), requirements);
                }
            }
        }
    }

    function testVerifyAmdSnpPlatformInfoPolicyMatrix() public {
        _register(GENOA_CPUID);
        bytes32 requireBitFour = bytes32(uint256(1) << 4);
        for (uint256 actualMode = 0; actualMode < 2; actualMode++) {
            for (uint256 baseMode = 0; baseMode < 3; baseMode++) {
                for (uint256 workloadMode = 0; workloadMode < 3; workloadMode++) {
                    VerifiedTeePolicyInputs memory inputs = _validInputs();
                    inputs.amdSevSnpPlatformInfo = actualMode == 0 ? 0x20 : 0x30;
                    Attribute[] memory attributes = new Attribute[](baseMode == 0 ? 0 : 1);
                    if (baseMode != 0) {
                        attributes[0] = Attribute(
                            TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, baseMode == 1 ? bytes32(0) : requireBitFour
                        );
                    }
                    AttributeRequirement[] memory requirements = new AttributeRequirement[](workloadMode == 0 ? 0 : 1);
                    if (workloadMode != 0) {
                        bytes32[] memory values = new bytes32[](1);
                        values[0] = workloadMode == 1 ? bytes32(0) : requireBitFour;
                        requirements[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, values);
                    }

                    bool basePermits = actualMode == 1 || baseMode != 2;
                    bool workloadPermits = actualMode == 1 || workloadMode != 2;
                    if (!basePermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                                requireBitFour,
                                bytes32(uint256(0x20))
                            )
                        );
                    } else if (!workloadPermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                                bytes32(uint256(0x20))
                            )
                        );
                    }
                    registry.verifyTeePolicy(inputs, attributes, new Attribute[](0), requirements);
                }
            }
        }
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

    /// @dev A boolean requirement is matched by value, not by the length of its allowed set.
    function testBooleanRequirementMustListTheVerifiedValue() public {
        _register(GENOA_CPUID);

        Attribute[] memory profile = new Attribute[](1);
        profile[0] = Attribute({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, value: TEE_ATTRIBUTE_TRUE});
        Attribute[] memory none = new Attribute[](0);

        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.enabledTeeAttributes = TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT;

        // Two allowed values that do not include `true` must not be read as an opt-in.
        bytes32[] memory wrongPair = new bytes32[](2);
        wrongPair[0] = bytes32(uint256(0xdead));
        wrongPair[1] = bytes32(uint256(0xbeef));
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: wrongPair});
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
                TEE_ATTRIBUTE_TRUE
            )
        );
        registry.verifyTeePolicy(inputs, profile, none, requirements);

        // A single-element set holding `true` is a valid opt-in regardless of its length.
        bytes32[] memory onlyTrue = new bytes32[](1);
        onlyTrue[0] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: onlyTrue});
        registry.verifyTeePolicy(inputs, profile, none, requirements);

        // The canonical WorkloadRegistry encoding still works.
        bytes32[] memory bothValues = new bytes32[](2);
        bothValues[0] = bytes32(0);
        bothValues[1] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: bothValues});
        registry.verifyTeePolicy(inputs, profile, none, requirements);
    }

    /// @dev A workload that states a requirement on a reserved key must name the value it
    ///      requires. An empty allowed set is malformed input, not a silent "no opinion" —
    ///      deferring to the registry default is what omitting the requirement means.
    function testEmptyAllowedValuesOnReservedKeyIsRejected() public {
        _register(GENOA_CPUID);

        Attribute[] memory none = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);

        // Packed key.
        requirements[0] =
            AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues: new bytes32[](0)});
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.EmptyTeeAttributeRequirement.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM
            )
        );
        registry.verifyTeePolicy(_validInputs(), none, none, requirements);

        // Boolean key, in the disabled state that would otherwise have been trivially accepted.
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: new bytes32[](0)});
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.EmptyTeeAttributeRequirement.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            )
        );
        registry.verifyTeePolicy(_validInputs(), none, none, requirements);

        // Omitting the requirement altogether is the supported way to defer to the default.
        AttributeRequirement[] memory noRequirements = new AttributeRequirement[](0);
        registry.verifyTeePolicy(_validInputs(), none, none, noRequirements);

        VerifiedTeePolicyInputs memory stale = _validInputs();
        stale.amdSevSnpTcbValues = bytes32(uint256(MINIMUM_TCB) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                stale.amdSevSnpTcbValues
            )
        );
        registry.verifyTeePolicy(stale, none, none, noRequirements);
    }

    function testPackedRequirementMustContainExactlyOneValue() public {
        _register(GENOA_CPUID);

        Attribute[] memory none = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        bytes32[] memory twoValues = new bytes32[](2);
        twoValues[0] = MINIMUM_TCB;
        twoValues[1] = MINIMUM_TCB;
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues: twoValues});

        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.InvalidPackedTeeAttributeRequirementLength.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                2
            )
        );
        registry.verifyTeePolicy(_validInputs(), none, none, requirements);
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

    function _validInputs() private pure returns (VerifiedTeePolicyInputs memory) {
        return VerifiedTeePolicyInputs({
            teeType: TEEType.AmdSevSnp,
            enabledTeeAttributes: 0,
            intelTdxTcbStatusBit: 0,
            amdSevSnpTcbValues: MINIMUM_TCB,
            amdSevSnpPlatformInfo: 0x20,
            amdSevSnpCpuid: GENOA_CPUID,
            amdSevSnpReportVersion: 3,
            amdSevSnpLaunchMitigationVector: 0,
            amdSevSnpCurrentMitigationVector: 0
        });
    }
}
