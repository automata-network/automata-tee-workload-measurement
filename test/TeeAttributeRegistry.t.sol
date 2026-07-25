// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {MockSignatureVerifier} from "../src/mock/MockSignatureVerifier.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    MeasurementVariant,
    PcrSpec,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";
import {
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
    TDX_TCB_STATUS_OK,
    TDX_TCB_STATUS_CONFIGURABLE_MASK,
    TEE_ATTRIBUTE_FALSE,
    TEE_ATTRIBUTE_TRUE
} from "../src/types/Constants.sol";

contract TeeAttributeRegistryTest is Test {
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;
    PublicIdentity private ownerIdentity;
    uint256 private nextVersion;
    uint256 private nextVariant;

    function setUp() public {
        vm.warp(1_800_000_000);
        MockSignatureVerifier signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        ownerIdentity = PublicIdentity({typeId: 1, key: hex"01020304"});
    }

    function test_reserved_attribute_hash_vectors_and_boolean_encoding() public pure {
        assertEq(
            TEE_ATTRIBUTE_INTEL_TDX_DEBUG, bytes32(0xe96023946a6ad61275cb45a796a2905e3d923139ce33b7734f3bea4eec3d72cd)
        );
        assertEq(
            TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, bytes32(0xe3517680fe2d4f15751da85b0400ea909bb3d5ae76232c10a6c447031d6389b9)
        );
        assertEq(
            TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
            bytes32(0x9090b994ea4098b565ee0da01c4bcaa083a5bfb19c0a797c7ffe3de7ce0251e1)
        );
        assertEq(
            TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
            bytes32(0xbc505eab3cf5643bdf24f1dee86998cd93d05a297e4c34f5e8f37bba764a8116)
        );
        assertEq(TEE_ATTRIBUTE_FALSE, bytes32(0));
        assertEq(TEE_ATTRIBUTE_TRUE, bytes32(uint256(1)));
    }

    function test_base_image_accepts_missing_false_and_true_reserved_attributes() public {
        _registerBaseImage(new Attribute[](0));
        _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_FALSE));
        _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_TRUE));
    }

    function test_base_image_rejects_malformed_reserved_attribute_value() public {
        bytes32 actual = bytes32(uint256(2));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidTeeAttributeValue.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, actual
            )
        );
        _registerBaseImage(_attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, actual));
    }

    function test_base_image_accepts_missing_and_valid_tdx_tcb_masks() public {
        _registerBaseImage(new Attribute[](0));
        _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK)));
        _registerBaseImage(
            _attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_CONFIGURABLE_MASK))
        );
    }

    function test_base_image_rejects_invalid_tdx_tcb_masks() public {
        bytes32[4] memory invalidMasks =
            [bytes32(0), bytes32(uint256(2)), bytes32(uint256(0x41)), bytes32(uint256(0x401))];
        for (uint256 i = 0; i < invalidMasks.length; i++) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    BaseImageRegistry.InvalidTeeAttributeValue.selector,
                    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                    invalidMasks[i]
                )
            );
            _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, invalidMasks[i]));
        }
    }

    function test_tdx_tcb_policy_is_not_allowed_in_measurement_variants() public {
        bytes32 baseImageId =
            _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK)));

        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeNotAllowedInMeasurementVariant.selector,
                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED
            )
        );
        _addPlatformVariant(
            baseImageId,
            "test-platform",
            new Attribute[](0),
            _attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK))
        );
    }

    function test_add_platform_variants_rejects_relaxed_tdx_tcb_mask_on_new_profile() public {
        bytes32 baseImageId = _registerBaseImage(new Attribute[](0));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeOptInRequiresNewBaseImage.selector,
                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED
            )
        );
        _addPlatformVariant(
            baseImageId,
            "new-platform",
            _attributes(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(uint256(3))),
            new Attribute[](0)
        );
    }

    function test_add_platform_variants_rejects_true_reserved_attribute_on_new_profile() public {
        bytes32 baseImageId = _registerBaseImage(new Attribute[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeOptInRequiresNewBaseImage.selector, TEE_ATTRIBUTE_INTEL_TDX_DEBUG
            )
        );
        _addPlatformVariant(
            baseImageId,
            "new-platform",
            _attributes(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_TRUE),
            new Attribute[](0)
        );
    }

    function test_add_platform_variants_rejects_true_reserved_variant_attribute_on_new_profile() public {
        bytes32 baseImageId = _registerBaseImage(new Attribute[](0));

        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeOptInRequiresNewBaseImage.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            )
        );
        _addPlatformVariant(
            baseImageId,
            "new-platform",
            new Attribute[](0),
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_TRUE)
        );
    }

    function test_add_platform_variants_rejects_true_variant_when_stored_profile_is_missing_or_false() public {
        bytes32 missingBaseImageId = _registerBaseImage(new Attribute[](0));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeOptInRequiresNewBaseImage.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA
            )
        );
        _addPlatformVariant(
            missingBaseImageId,
            "test-platform",
            new Attribute[](0),
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, TEE_ATTRIBUTE_TRUE)
        );

        bytes32 falseBaseImageId =
            _registerBaseImage(_attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, TEE_ATTRIBUTE_FALSE));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.TeeAttributeOptInRequiresNewBaseImage.selector, TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA
            )
        );
        _addPlatformVariant(
            falseBaseImageId,
            "test-platform",
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, TEE_ATTRIBUTE_TRUE),
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, TEE_ATTRIBUTE_TRUE)
        );
    }

    function test_add_platform_variants_allows_inherited_or_explicit_true_when_stored_profile_is_true() public {
        bytes32 baseImageId = _registerBaseImage(_attributes(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_TRUE));

        _addPlatformVariant(baseImageId, "test-platform", new Attribute[](0), new Attribute[](0));
        _addPlatformVariant(
            baseImageId,
            "test-platform",
            new Attribute[](0),
            _attributes(TEE_ATTRIBUTE_INTEL_TDX_DEBUG, TEE_ATTRIBUTE_TRUE)
        );
    }

    function test_add_platform_variants_allows_false_and_ordinary_attributes() public {
        bytes32 baseImageId = _registerBaseImage(new Attribute[](0));

        _addPlatformVariant(
            baseImageId,
            "new-platform",
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_FALSE),
            _attributes(keccak256("ordinary.metadata"), TEE_ATTRIBUTE_TRUE)
        );
        _addPlatformVariant(
            baseImageId,
            "test-platform",
            new Attribute[](0),
            _attributes(TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_FALSE)
        );
    }

    function test_workload_accepts_missing_false_and_false_true_reserved_requirements() public {
        _registerWorkload(new AttributeRequirement[](0));
        _registerWorkload(_requirements(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, _values(false, false)));
        _registerWorkload(_requirements(TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA, _values(false, true)));
    }

    function test_workload_rejects_every_malformed_reserved_requirement_shape() public {
        bytes32 key = TEE_ATTRIBUTE_INTEL_TDX_DEBUG;

        _expectRequirementLength(key, new bytes32[](0), 0);
        _expectRequirementValue(key, _singleValue(TEE_ATTRIBUTE_TRUE), TEE_ATTRIBUTE_TRUE);
        _expectRequirementValue(key, _pairValues(TEE_ATTRIBUTE_FALSE, TEE_ATTRIBUTE_FALSE), TEE_ATTRIBUTE_FALSE);
        _expectRequirementValue(key, _pairValues(TEE_ATTRIBUTE_TRUE, TEE_ATTRIBUTE_FALSE), TEE_ATTRIBUTE_TRUE);
        _expectRequirementValue(key, _pairValues(TEE_ATTRIBUTE_TRUE, TEE_ATTRIBUTE_TRUE), TEE_ATTRIBUTE_TRUE);
        _expectRequirementValue(key, _singleValue(bytes32(uint256(2))), bytes32(uint256(2)));

        bytes32[] memory threeValues = new bytes32[](3);
        threeValues[0] = TEE_ATTRIBUTE_FALSE;
        threeValues[1] = TEE_ATTRIBUTE_TRUE;
        threeValues[2] = TEE_ATTRIBUTE_FALSE;
        _expectRequirementLength(key, threeValues, 3);
    }

    function test_workload_keeps_empty_allowed_values_for_ordinary_metadata() public {
        bytes32 ordinaryKey = keccak256("ordinary.metadata");
        _registerWorkload(_requirements(ordinaryKey, new bytes32[](0)));
    }

    function test_workload_accepts_valid_tdx_tcb_masks() public {
        _registerWorkload(
            _requirements(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, _singleValue(bytes32(TDX_TCB_STATUS_OK)))
        );
        _registerWorkload(
            _requirements(
                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, _singleValue(bytes32(TDX_TCB_STATUS_CONFIGURABLE_MASK))
            )
        );
    }

    function test_workload_rejects_invalid_tdx_tcb_requirement_shapes_and_masks() public {
        _expectRequirementLength(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, new bytes32[](0), 0);
        _expectRequirementLength(
            TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, _pairValues(bytes32(TDX_TCB_STATUS_OK), bytes32(uint256(3))), 2
        );
        _expectRequirementValue(TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, _singleValue(bytes32(0)), bytes32(0));
        _expectRequirementValue(
            TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, _singleValue(bytes32(uint256(0x401))), bytes32(uint256(0x401))
        );
    }

    function _expectRequirementLength(bytes32 key, bytes32[] memory values, uint256 actualLength) private {
        vm.expectRevert(
            abi.encodeWithSelector(WorkloadRegistry.InvalidTeeAttributeRequirementLength.selector, key, actualLength)
        );
        _registerWorkload(_requirements(key, values));
    }

    function _expectRequirementValue(bytes32 key, bytes32[] memory values, bytes32 actualValue) private {
        vm.expectRevert(
            abi.encodeWithSelector(WorkloadRegistry.InvalidTeeAttributeRequirementValue.selector, key, actualValue)
        );
        _registerWorkload(_requirements(key, values));
    }

    function _registerBaseImage(Attribute[] memory attributes) private returns (bytes32) {
        nextVersion++;
        BaseImageSpec memory spec =
            BaseImageSpec({name: "tee-attribute-base", version: vm.toString(nextVersion), uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({name: "test-platform", invariants: new PcrSpec[](0), attributes: attributes});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] =
            MeasurementVariant({name: "test-variant", overridePcrs: new PcrSpec[](0), attributes: new Attribute[](0)});
        return baseImageRegistry.registerBaseImage(
            spec, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function _registerWorkload(AttributeRequirement[] memory requirements) private returns (bytes32) {
        nextVersion++;
        WorkloadSpec memory spec = WorkloadSpec({
            name: "tee-attribute-workload",
            version: vm.toString(nextVersion),
            sessionTtl: 1 days,
            baseImageMode: AccessMode.ANY,
            baseImageIds: new bytes32[](0),
            requirements: requirements,
            pcrs: new PcrSpec[](0)
        });
        return workloadRegistry.registerWorkload(spec, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
    }

    function _addPlatformVariant(
        bytes32 baseImageId,
        string memory profileName,
        Attribute[] memory profileAttributes,
        Attribute[] memory variantAttributes
    ) private {
        nextVariant++;
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({name: profileName, invariants: new PcrSpec[](0), attributes: profileAttributes});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: string.concat("appended-variant-", vm.toString(nextVariant)),
            overridePcrs: new PcrSpec[](0),
            attributes: variantAttributes
        });
        baseImageRegistry.addPlatformVariants(
            baseImageId, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function _attributes(bytes32 key, bytes32 value) private pure returns (Attribute[] memory attributes) {
        attributes = new Attribute[](1);
        attributes[0] = Attribute({key: key, value: value});
    }

    function _requirements(bytes32 key, bytes32[] memory values)
        private
        pure
        returns (AttributeRequirement[] memory requirements)
    {
        requirements = new AttributeRequirement[](1);
        requirements[0] = AttributeRequirement({key: key, allowedValues: values});
    }

    function _values(bool first, bool second) private pure returns (bytes32[] memory values) {
        values = new bytes32[](second ? 2 : 1);
        values[0] = first ? TEE_ATTRIBUTE_TRUE : TEE_ATTRIBUTE_FALSE;
        if (second) values[1] = TEE_ATTRIBUTE_TRUE;
    }

    function _singleValue(bytes32 value) private pure returns (bytes32[] memory values) {
        values = new bytes32[](1);
        values[0] = value;
    }

    function _pairValues(bytes32 first, bytes32 second) private pure returns (bytes32[] memory values) {
        values = new bytes32[](2);
        values[0] = first;
        values[1] = second;
    }
}
