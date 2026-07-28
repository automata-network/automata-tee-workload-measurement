// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    MeasurementVariant,
    PcrSpec,
    PcrVerifyType,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";

contract PcrStaticCardinalityTest is Test {
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;
    PublicIdentity private ownerIdentity;
    uint256 private nextVersion;

    function setUp() public {
        vm.warp(1_800_000_000);
        MockSignatureVerifier signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        ownerIdentity = PublicIdentity({typeId: 1, key: hex"01020304"});
    }

    function testRegisterBaseImageRejectsStaticWithZeroOrMultipleMatchDataEntries() public {
        _expectBaseImageStaticLength(0);
        _expectBaseImageStaticLength(2);
    }

    function testRegisterBaseImageRejectsVariantStaticWithMultipleMatchDataEntries() public {
        PcrSpec[] memory variantPcrs = _staticPcrs(4, 2);
        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.InvalidStaticMatchDataLength.selector, uint8(4), uint256(2))
        );
        _registerBaseImage(new PcrSpec[](0), variantPcrs);
    }

    function testAddPlatformVariantsRejectsStaticWithMultipleMatchDataEntries() public {
        bytes32 baseImageId = _registerBaseImage(new PcrSpec[](0), new PcrSpec[](0));
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] =
            PlatformProfile({name: "new-profile", invariants: _staticPcrs(4, 2), attributes: new Attribute[](0)});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](0);

        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.InvalidStaticMatchDataLength.selector, uint8(4), uint256(2))
        );
        baseImageRegistry.addPlatformVariants(
            baseImageId, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function testRegisterWorkloadRejectsStaticWithZeroOrMultipleMatchDataEntries() public {
        _expectWorkloadStaticLength(0);
        _expectWorkloadStaticLength(2);
    }

    function testRegistriesAcceptStaticWithExactlyOneMatchDataEntry() public {
        _registerBaseImage(_staticPcrs(4, 1), new PcrSpec[](0));
        _registerWorkload(_staticPcrs(23, 1));
    }

    function _expectBaseImageStaticLength(uint256 length) private {
        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.InvalidStaticMatchDataLength.selector, uint8(4), length)
        );
        _registerBaseImage(_staticPcrs(4, length), new PcrSpec[](0));
    }

    function _expectWorkloadStaticLength(uint256 length) private {
        vm.expectRevert(
            abi.encodeWithSelector(WorkloadRegistry.InvalidStaticMatchDataLength.selector, uint8(23), length)
        );
        _registerWorkload(_staticPcrs(23, length));
    }

    function _registerBaseImage(PcrSpec[] memory invariants, PcrSpec[] memory variantPcrs) private returns (bytes32) {
        nextVersion++;
        BaseImageSpec memory spec =
            BaseImageSpec({name: "static-cardinality-base", version: vm.toString(nextVersion), uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({name: "test-profile", invariants: invariants, attributes: new Attribute[](0)});
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] =
            MeasurementVariant({name: "test-variant", overridePcrs: variantPcrs, attributes: new Attribute[](0)});
        return baseImageRegistry.registerBaseImage(
            spec, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function _registerWorkload(PcrSpec[] memory pcrs) private returns (bytes32) {
        nextVersion++;
        WorkloadSpec memory spec = WorkloadSpec({
            name: "static-cardinality-workload",
            version: vm.toString(nextVersion),
            sessionTtl: 1 days,
            baseImageMode: AccessMode.ANY,
            baseImageIds: new bytes32[](0),
            requirements: new AttributeRequirement[](0),
            pcrs: pcrs
        });
        return workloadRegistry.registerWorkload(spec, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
    }

    function _staticPcrs(uint8 pcrIndex, uint256 length) private pure returns (PcrSpec[] memory pcrs) {
        bytes32[] memory matchData = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            matchData[i] = bytes32(i + 1);
        }
        pcrs = new PcrSpec[](1);
        pcrs[0] = PcrSpec({pcrIndex: pcrIndex, verifyType: PcrVerifyType.STATIC, matchData: matchData});
    }
}
