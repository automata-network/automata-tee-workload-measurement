// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
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

    function testDeactivatePreservesPolicyAndReactivateRequiresNewRevision() public {
        _register(GENOA_CPUID);
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 2, false, bytes32(0), bytes32(0));

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

        updates[0] = AmdSnpSecurityPolicyUpdate(GENOA_CPUID, 1, false, bytes32(0), bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(AmdSnpSecurityPolicyRegistry.PolicyNotFound.selector, GENOA_CPUID));
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);
    }

    function testPackedTcbHelpersCompareEachComponent() public pure {
        bytes32 lower = bytes32(uint256(MINIMUM_TCB) - 1);
        assertTrue(AmdSnpPolicy.tcbMeetsMinimum(MINIMUM_TCB, lower));
        assertFalse(AmdSnpPolicy.tcbMeetsMinimum(lower, MINIMUM_TCB));
        assertEq(AmdSnpPolicy.maxTcb(lower, MINIMUM_TCB), MINIMUM_TCB);
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

    function testVerifyAmdSnpPolicyEnforcesGlobalFloor() public {
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

    function testVerifyAmdSnpPolicyAppliesVariantOverrideWithoutWeakeningGlobalFloor() public {
        _register(GENOA_CPUID);
        Attribute[] memory profileAttributes = new Attribute[](1);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, bytes32(uint256(MINIMUM_TCB) + 1));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, bytes32(0));

        registry.verifyTeePolicy(_validInputs(), profileAttributes, variantAttributes, new AttributeRequirement[](0));

        variantAttributes = new Attribute[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                bytes32(uint256(MINIMUM_TCB) + 1),
                MINIMUM_TCB
            )
        );
        registry.verifyTeePolicy(_validInputs(), profileAttributes, variantAttributes, new AttributeRequirement[](0));
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
        vm.expectRevert(
            abi.encodeWithSelector(
                AmdSnpSecurityPolicyRegistry.TeeAttributePolicyConflict.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                PLATFORM_INFO_POLICY,
                bytes32(uint256(1))
            )
        );
        registry.verifyTeePolicy(_validInputs(), attributes, new Attribute[](0), new AttributeRequirement[](0));
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
        bytes32 globalAndBitFour = bytes32(uint256(0x30) | (uint256(1) << 64));

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
                                globalAndBitFour,
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

    function _register(uint24 cpuid) private {
        AmdSnpSecurityPolicyUpdate[] memory updates = new AmdSnpSecurityPolicyUpdate[](1);
        updates[0] = _activeUpdate(cpuid, 1);
        vm.prank(OWNER);
        registry.updatePolicies(updates, SOURCE_DIGEST);
    }

    function _activeUpdate(uint24 cpuid, uint64 revision) private pure returns (AmdSnpSecurityPolicyUpdate memory) {
        return AmdSnpSecurityPolicyUpdate(cpuid, revision, true, MINIMUM_TCB, PLATFORM_INFO_POLICY);
    }

    function _validInputs() private pure returns (VerifiedTeePolicyInputs memory) {
        return VerifiedTeePolicyInputs({
            teeType: TEEType.AmdSevSnp,
            enabledTeeAttributes: 0,
            intelTdxTcbStatusBit: 0,
            amdSevSnpTcbValues: MINIMUM_TCB,
            amdSevSnpPlatformInfo: 0x20,
            amdSevSnpCpuid: GENOA_CPUID
        });
    }
}
