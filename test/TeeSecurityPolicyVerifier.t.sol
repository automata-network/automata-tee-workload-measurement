// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {TeeSecurityPolicyVerifier} from "../src/TeeSecurityPolicyVerifier.sol";
import {AmdSnpSecurityPolicyUpdate} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {VerifiedTeePolicyInputs} from "../src/interfaces/ITeeSecurityPolicyVerifier.sol";
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

contract TeeSecurityPolicyVerifierTest is Test {
    address private constant OWNER = address(0x1234);
    uint24 private constant MILAN_CPUID = 0x190101;
    uint24 private constant GENOA_CPUID = 0x191101;
    bytes32 private constant MINIMUM_TCB = 0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004;
    bytes32 private constant PLATFORM_INFO_POLICY = 0x0000000000000000000000000000000000000000000000010000000000000020;
    bytes32 private constant SOURCE_DIGEST = keccak256("policy-source");

    AmdSnpSecurityPolicyRegistry private registry;
    TeeSecurityPolicyVerifier private verifier;

    function setUp() public {
        AmdSnpSecurityPolicyRegistry implementation = new AmdSnpSecurityPolicyRegistry();
        registry = AmdSnpSecurityPolicyRegistry(
            address(new ERC1967Proxy(address(implementation), abi.encodeCall(implementation.initialize, (OWNER))))
        );
        verifier = new TeeSecurityPolicyVerifier(registry);
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
                TeeSecurityPolicyVerifier.SnpMitigationPolicyRequiresReportVersion.selector, uint32(3), uint32(5)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpReportVersion = 6;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.SnpMitigationPolicyRequiresReportVersion.selector, uint32(6), uint32(5)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpReportVersion = 5;
        inputs.amdSevSnpLaunchMitigationVector = 0x07;
        inputs.amdSevSnpCurrentMitigationVector = 0x0d;
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x02;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.SnpLaunchMitigationVectorMissing.selector, uint64(0x03), uint64(0x02)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x03;
        inputs.amdSevSnpCurrentMitigationVector = 0x04;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.SnpCurrentMitigationVectorMissing.selector, uint64(0x05), uint64(0x04)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);
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
                TeeSecurityPolicyVerifier.SnpLaunchMitigationVectorMissing.selector, uint64(0x16), uint64(0x0f)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpLaunchMitigationVector = 0x16;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.SnpCurrentMitigationVectorMissing.selector, uint64(0x16), uint64(0x0f)
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpCurrentMitigationVector = 0x16;
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);
    }

    function testZeroMitigationMasksAcceptVersionThreeReport() public {
        _register(GENOA_CPUID);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        assertEq(inputs.amdSevSnpReportVersion, 3);

        Attribute[] memory attributes = new Attribute[](0);
        verifier.verifyTeePolicy(inputs, attributes, attributes, new AttributeRequirement[](0));
    }

    function testVerifyAmdSnpPolicyUsesRegistryDefaultsWhenBothSidesAreMissing() public {
        _register(GENOA_CPUID);
        Attribute[] memory attributes = new Attribute[](0);
        AttributeRequirement[] memory requirements = new AttributeRequirement[](0);
        VerifiedTeePolicyInputs memory inputs = _validInputs();

        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs.amdSevSnpTcbValues = bytes32(uint256(MINIMUM_TCB) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                inputs.amdSevSnpTcbValues
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);

        inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x21;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                PLATFORM_INFO_POLICY,
                bytes32(uint256(0x21))
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, attributes, requirements);
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

        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        variantAttributes = new Attribute[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                bytes32(uint256(MINIMUM_TCB) + 1),
                lowerTcb
            )
        );
        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
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
                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                lowerTcb
            )
        );
        verifier.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), new AttributeRequirement[](0));

        bytes32[] memory allowedValues = new bytes32[](1);
        allowedValues[0] = lowerTcb;
        AttributeRequirement[] memory lowerWorkload = new AttributeRequirement[](1);
        lowerWorkload[0] = AttributeRequirement(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, allowedValues);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                lowerTcb
            )
        );
        verifier.verifyTeePolicy(inputs, new Attribute[](0), new Attribute[](0), lowerWorkload);
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

        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
    }

    function testVerifyAmdSnpPlatformInfoPolicyAppliesWholeVariantOverride() public {
        _register(GENOA_CPUID);
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x30;
        Attribute[] memory profileAttributes = new Attribute[](1);
        profileAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1) << 68));
        Attribute[] memory variantAttributes = new Attribute[](1);
        variantAttributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1) << 4));

        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, new AttributeRequirement[](0));

        bytes32 effectiveProfilePolicy = bytes32(uint256(1) << 68);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                effectiveProfilePolicy,
                bytes32(uint256(0x30))
            )
        );
        verifier.verifyTeePolicy(inputs, profileAttributes, new Attribute[](0), new AttributeRequirement[](0));
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
                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB
            )
        );
        verifier.verifyTeePolicy(_validInputs(), attributes, attributes, requirements);

        attributes = new Attribute[](1);
        attributes[0] = Attribute(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(1)));
        VerifiedTeePolicyInputs memory inputs = _validInputs();
        inputs.amdSevSnpPlatformInfo = 0x21;
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributePolicyConflict.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                bytes32(uint256(1)),
                PLATFORM_INFO_POLICY
            )
        );
        verifier.verifyTeePolicy(inputs, attributes, new Attribute[](0), new AttributeRequirement[](0));
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

        verifier.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), lowerWorkload);

        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                bytes32(0)
            )
        );
        verifier.verifyTeePolicy(inputs, lowerBase, new Attribute[](0), new AttributeRequirement[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                PLATFORM_INFO_POLICY,
                bytes32(0)
            )
        );
        verifier.verifyTeePolicy(inputs, new Attribute[](0), new Attribute[](0), lowerWorkload);
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

        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        customValues[0] = bytes32(uint256(1));
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.AttributeValueNotAllowed.selector, customKey, bytes32(uint256(2))
            )
        );
        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);

        requirements[1].key = keccak256("example.missing");
        vm.expectRevert(
            abi.encodeWithSelector(TeeSecurityPolicyVerifier.AttributeNotFound.selector, requirements[1].key)
        );
        verifier.verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements);
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
                                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                                strongerTcb,
                                MINIMUM_TCB
                            )
                        );
                    } else if (!workloadPermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                                MINIMUM_TCB
                            )
                        );
                    }
                    verifier.verifyTeePolicy(inputs, attributes, new Attribute[](0), requirements);
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
                                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                                requireBitFour,
                                bytes32(uint256(0x20))
                            )
                        );
                    } else if (!workloadPermits) {
                        vm.expectRevert(
                            abi.encodeWithSelector(
                                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                                bytes32(uint256(0x20))
                            )
                        );
                    }
                    verifier.verifyTeePolicy(inputs, attributes, new Attribute[](0), requirements);
                }
            }
        }
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
                TeeSecurityPolicyVerifier.TeeAttributeValueNotAllowed.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
                TEE_ATTRIBUTE_TRUE
            )
        );
        verifier.verifyTeePolicy(inputs, profile, none, requirements);

        // A single-element set holding `true` is a valid opt-in regardless of its length.
        bytes32[] memory onlyTrue = new bytes32[](1);
        onlyTrue[0] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: onlyTrue});
        verifier.verifyTeePolicy(inputs, profile, none, requirements);

        // The canonical WorkloadRegistry encoding still works.
        bytes32[] memory bothValues = new bytes32[](2);
        bothValues[0] = bytes32(0);
        bothValues[1] = TEE_ATTRIBUTE_TRUE;
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: bothValues});
        verifier.verifyTeePolicy(inputs, profile, none, requirements);
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
                TeeSecurityPolicyVerifier.EmptyTeeAttributeRequirement.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM
            )
        );
        verifier.verifyTeePolicy(_validInputs(), none, none, requirements);

        // Boolean key, in the disabled state that would otherwise have been trivially accepted.
        requirements[0] = AttributeRequirement({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, allowedValues: new bytes32[](0)});
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.EmptyTeeAttributeRequirement.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            )
        );
        verifier.verifyTeePolicy(_validInputs(), none, none, requirements);

        // Omitting the requirement altogether is the supported way to defer to the default.
        AttributeRequirement[] memory noRequirements = new AttributeRequirement[](0);
        verifier.verifyTeePolicy(_validInputs(), none, none, noRequirements);

        VerifiedTeePolicyInputs memory stale = _validInputs();
        stale.amdSevSnpTcbValues = bytes32(uint256(MINIMUM_TCB) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TeeSecurityPolicyVerifier.TeeAttributeBaseImageMismatch.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                MINIMUM_TCB,
                stale.amdSevSnpTcbValues
            )
        );
        verifier.verifyTeePolicy(stale, none, none, noRequirements);
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
                TeeSecurityPolicyVerifier.InvalidPackedTeeAttributeRequirementLength.selector,
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
                2
            )
        );
        verifier.verifyTeePolicy(_validInputs(), none, none, requirements);
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
