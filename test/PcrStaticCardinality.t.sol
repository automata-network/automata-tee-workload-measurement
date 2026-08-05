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
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";

contract PcrOpaqueComparisonRegistrationTest is Test {
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

    function testRegisterBaseImageRejectsEmptyComparison() public {
        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.EmptyPcrComparison.selector, uint8(4)));
        _registerBaseImage(_pcrs(4, hex""), new PcrSpec256[](0));
    }

    function testRegisterBaseImageRejectsEmptyVariantComparison() public {
        PcrSpec256[] memory variantPcrs = _pcrs(4, hex"");
        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.EmptyPcrComparison.selector, uint8(4)));
        _registerBaseImage(new PcrSpec256[](0), variantPcrs);
    }

    function testAddPlatformVariantsRejectsEmptyComparison() public {
        bytes32 baseImageId = _registerBaseImage(new PcrSpec256[](0), new PcrSpec256[](0));
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "new-profile",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariantPcrs256: _pcrs(4, hex""),
            invariantPcrs384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](0);

        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.EmptyPcrComparison.selector, uint8(4)));
        baseImageRegistry.addPlatformVariants(
            baseImageId, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function testRegisterWorkloadRejectsEmptyComparison() public {
        vm.expectRevert(abi.encodeWithSelector(WorkloadRegistry.EmptyPcrComparison.selector, uint8(23)));
        _registerWorkload(_pcrs(23, hex""));
    }

    function testRegistriesPassNonEmptyComparisonWithoutDecodingIt() public {
        bytes memory opaqueComparison = hex"deadbeef";
        _registerBaseImage(_pcrs(4, opaqueComparison), new PcrSpec256[](0));
        _registerWorkload(_pcrs(23, opaqueComparison));
    }

    function _registerBaseImage(PcrSpec256[] memory invariants, PcrSpec256[] memory variantPcrs)
        private
        returns (bytes32)
    {
        nextVersion++;
        BaseImageSpec memory spec =
            BaseImageSpec({name: "static-cardinality-base", version: vm.toString(nextVersion), uri: ""});
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "test-profile",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariantPcrs256: invariants,
            invariantPcrs384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: "test-variant",
            variantPcrs256: variantPcrs,
            variantPcrs384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
        return baseImageRegistry.registerBaseImage(
            spec, profiles, variants, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01"
        );
    }

    function _registerWorkload(PcrSpec256[] memory pcrs) private returns (bytes32) {
        nextVersion++;
        WorkloadSpec memory spec = WorkloadSpec({
            name: "static-cardinality-workload",
            version: vm.toString(nextVersion),
            sessionTtl: 1 days,
            baseImageMode: AccessMode.ANY,
            baseImageIds: new bytes32[](0),
            requirements: new AttributeRequirement[](0),
            workloadPcrs256: pcrs,
            workloadPcrs384: new PcrSpec384[](0)
        });
        return workloadRegistry.registerWorkload(spec, uint64(block.timestamp + 1 hours), ownerIdentity, hex"01");
    }

    function _pcrs(uint8 pcrIndex, bytes memory comparison) private pure returns (PcrSpec256[] memory pcrs) {
        pcrs = new PcrSpec256[](1);
        pcrs[0] = PcrSpec256({pcrIndex: pcrIndex, comparison: comparison});
    }
}
