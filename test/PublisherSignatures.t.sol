// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {SignedBaseImageVariant} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {SignedWorkload} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {PcrComparison} from "../src/lib/PcrComparison.sol";
import {PublisherPolicy} from "../src/lib/PublisherPolicy.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    MeasurementVariant,
    PcrBankSelection,
    PcrPolicyBlock,
    PcrSpec256,
    PcrSpec384,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";
import {
    ALGO_ID_ES256K,
    BASEIMAGE_DOMAIN,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    WORKLOAD_DOMAIN,
    BASEIMAGE_REGISTER_MSG,
    BASEIMAGE_UPDATE_MSG,
    WORKLOAD_REGISTER_MSG,
    BASEIMAGE_REGISTER_MSG_V2,
    BASEIMAGE_UPDATE_MSG_V2,
    WORKLOAD_REGISTER_MSG_V2,
    BASEIMAGE_VARIANT_SIGNATURE_DOMAIN,
    WORKLOAD_POLICY_SIGNATURE_DOMAIN
} from "../src/types/Constants.sol";

/// @notice Real publisher signatures, different image/workload publishers, and legacy ABI coverage.
contract PublisherSignaturesTest is Test {
    uint256 internal constant IMAGE_KEY = 0xB0B;
    uint256 internal constant WORKLOAD_KEY = 0xA11CE;
    BaseImageRegistry internal images;
    WorkloadRegistry internal workloads;
    SignatureVerifier internal verifier;
    PublicIdentity internal imageOwner;
    PublicIdentity internal workloadOwner;
    uint64 internal deadline;
    bytes private expectedRegistryRevert;

    // Prepare signatures before arming expectRevert: SHA-256 invokes a precompile.
    function _expectContractRevert(bytes memory reason) private {
        expectedRegistryRevert = reason;
    }

    function _expectNextRegistryCall() private {
        if (expectedRegistryRevert.length != 0) {
            bytes memory reason = expectedRegistryRevert;
            delete expectedRegistryRevert;
            vm.expectRevert(reason);
        }
    }

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        verifier = new SignatureVerifier(address(0x100));
        images = BaseImageRegistry(
            address(
                new ERC1967Proxy(
                    address(new BaseImageRegistry(verifier)),
                    abi.encodeCall(BaseImageRegistry.initialize, (address(this)))
                )
            )
        );
        workloads = WorkloadRegistry(
            address(
                new ERC1967Proxy(
                    address(new WorkloadRegistry(verifier)),
                    abi.encodeCall(WorkloadRegistry.initialize, (address(this)))
                )
            )
        );
        imageOwner = _identity(IMAGE_KEY);
        workloadOwner = _identity(WORKLOAD_KEY);
        bytes32[] memory fps = new bytes32[](1);
        fps[0] = LibKey.computeKeyFingerprint(imageOwner);
        images.addToWhitelist(fps);
        fps[0] = LibKey.computeKeyFingerprint(workloadOwner);
        workloads.addToWhitelist(fps);
        deadline = uint64(block.timestamp + 1 hours);
    }

    function _identity(uint256 key) internal returns (PublicIdentity memory) {
        Vm.Wallet memory w = vm.createWallet(key);
        return PublicIdentity(ALGO_ID_ES256K, abi.encodePacked(bytes1(0x04), w.publicKeyX, w.publicKeyY));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _pcr(uint8 index, bytes32 value) internal pure returns (PcrPolicyBlock memory block_) {
        block_.pcrSpecs256 = new PcrSpec256[](1);
        block_.pcrSpecs256[0] = PcrSpec256(index, PcrComparison.encodeStatic256(value));
        block_.pcrSpecs384 = new PcrSpec384[](0);
    }

    function _data()
        internal
        pure
        virtual
        returns (BaseImageSpec memory spec, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants)
    {
        spec = BaseImageSpec("publisher-signature-test", "v0.3.5-debug", "ipfs://test");
        profiles = new PlatformProfile[](2);
        variants = new MeasurementVariant[][](2);
        for (uint256 i; i < 2; ++i) {
            Attribute[] memory attributes = new Attribute[](1);
            attributes[0] = Attribute(keccak256("cloud"), bytes32(i + 1));
            profiles[i] = PlatformProfile(
                i == 0 ? "aws-sev-snp" : "gcp-tdx",
                PcrBankSelection.Sha256,
                _pcr(4, bytes32(uint256(100 + i))),
                attributes
            );
            variants[i] = new MeasurementVariant[](i == 0 ? 2 : 1);
            for (uint256 j; j < variants[i].length; ++j) {
                Attribute[] memory attrs = new Attribute[](1);
                attrs[0] = Attribute(keccak256("machine"), bytes32(j + 1));
                variants[i][j] = MeasurementVariant(
                    i == 1 ? "c3-standard-4" : j == 0 ? "m6a.large" : "m6a.xlarge",
                    _pcr(0, bytes32(uint256(200 + i * 10 + j))),
                    attrs
                );
            }
        }
    }

    function _imageId(BaseImageSpec memory spec) internal view returns (bytes32) {
        return
            keccak256(abi.encode(BASEIMAGE_DOMAIN, LibKey.computeKeyFingerprint(imageOwner), spec.name, spec.version));
    }

    function _profileId(bytes32 id, PlatformProfile memory profile) internal pure returns (bytes32) {
        return keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, id, profile.name));
    }

    function _variantId(bytes32 profileId, MeasurementVariant memory variant) internal pure returns (bytes32) {
        return keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, profileId, variant.name));
    }

    function _variantDigest(bytes32 id, PlatformProfile memory p, MeasurementVariant memory v)
        internal
        pure
        returns (bytes32)
    {
        // Independent ABI reconstruction rather than calling the production digest helper.
        return sha256(abi.encode(BASEIMAGE_VARIANT_SIGNATURE_DOMAIN, id, p, v));
    }

    function _signVariants(bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v)
        internal
        pure
        returns (bytes[][] memory sigs)
    {
        sigs = new bytes[][](p.length);
        for (uint256 i; i < p.length; ++i) {
            sigs[i] = new bytes[](v[i].length);
            for (uint256 j; j < v[i].length; ++j) {
                sigs[i][j] = _sign(IMAGE_KEY, _variantDigest(id, p[i], v[i][j]));
            }
        }
    }

    function _publish(
        BaseImageSpec memory s,
        PlatformProfile[] memory p,
        MeasurementVariant[][] memory v,
        bytes[][] memory sigs
    ) internal returns (bytes32) {
        bytes memory outer = _sign(
            IMAGE_KEY,
            sha256(abi.encode(BASEIMAGE_REGISTER_MSG_V2, block.chainid, address(images), deadline, s, p, v, sigs))
        );
        _expectNextRegistryCall();
        return images.registerBaseImageV2(s, p, v, sigs, deadline, imageOwner, outer);
    }

    function _registered() internal returns (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) {
        BaseImageSpec memory s;
        (s, p, v) = _data();
        id = _imageId(s);
        assertEq(_publish(s, p, v, _signVariants(id, p, v)), id);
    }

    function _append(bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v, bytes[][] memory sigs)
        internal
    {
        bytes memory outer = _sign(
            IMAGE_KEY,
            sha256(abi.encode(BASEIMAGE_UPDATE_MSG_V2, block.chainid, address(images), deadline, id, p, v, sigs))
        );
        _expectNextRegistryCall();
        images.addPlatformVariantsV2(id, p, v, sigs, deadline, imageOwner, outer);
    }

    function testPublishMultipleProfilesAndVariantsReadEachIndependently() public {
        (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _registered();
        for (uint256 i; i < p.length; ++i) {
            bytes32 pid = _profileId(id, p[i]);
            for (uint256 j; j < v[i].length; ++j) {
                SignedBaseImageVariant memory result = images.getSignedVariant(id, pid, _variantId(pid, v[i][j]));
                assertEq(abi.encode(result.platformProfile), abi.encode(p[i]));
                assertEq(abi.encode(result.measurementVariant), abi.encode(v[i][j]));
                assertEq(result.ownerFingerprint, LibKey.computeKeyFingerprint(result.ownerIdentity));
                assertTrue(
                    verifier.verify(
                        result.ownerIdentity,
                        _variantDigest(id, result.platformProfile, result.measurementVariant),
                        result.variantSignature
                    )
                );
            }
        }
    }

    function testAppendRetainsOldSignaturesAndUsesSameInnerFormat() public {
        (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _registered();
        bytes32 pid = _profileId(id, p[0]);
        bytes32 oldId = _variantId(pid, v[0][0]);
        bytes memory old = images.getSignedVariant(id, pid, oldId).variantSignature;
        v[0][0].name = "m6a.2xlarge";
        v[0][1].name = "m6a.4xlarge";
        v[1][0].name = "c3-standard-8";
        _append(id, p, v, _signVariants(id, p, v));
        assertEq(images.getSignedVariant(id, pid, oldId).variantSignature, old);
        SignedBaseImageVariant memory r = images.getSignedVariant(id, pid, _variantId(pid, v[0][0]));
        assertTrue(
            verifier.verify(
                r.ownerIdentity, _variantDigest(id, r.platformProfile, r.measurementVariant), r.variantSignature
            )
        );
    }

    function testExpiryBlocksPublicationButDoesNotExpireStoredPolicy() public {
        (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _registered();
        vm.warp(deadline + 1);
        bytes32 pid = _profileId(id, p[0]);
        SignedBaseImageVariant memory r = images.getSignedVariant(id, pid, _variantId(pid, v[0][0]));
        assertTrue(
            verifier.verify(
                r.ownerIdentity, _variantDigest(id, r.platformProfile, r.measurementVariant), r.variantSignature
            )
        );
        bytes[][] memory sigs = _signVariants(id, p, v);
        _expectContractRevert(
            abi.encodeWithSelector(BaseImageRegistry.SignatureExpired.selector, deadline, uint64(block.timestamp))
        );
        _append(id, p, v, sigs);
    }

    function testWrongPublisherCannotSupplyInnerSignature() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes32 id = _imageId(s);
        bytes[][] memory sigs = _signVariants(id, p, v);
        bytes32 digest = _variantDigest(id, p[0], v[0][0]);
        sigs[0][0] = _sign(WORKLOAD_KEY, digest);
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidVariantSignature.selector, digest, LibKey.computeKeyFingerprint(imageOwner)
            )
        );
        _publish(s, p, v, sigs);
        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.BaseImageNotFound.selector, id));
        images.getBaseImage(id);
    }

    function testFuzzSignedVariantBindsEveryPolicyField(uint8 selector, bytes32 mutation) public {
        vm.assume(mutation != bytes32(0));
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes32 id = _imageId(s);
        bytes[][] memory sigs = _signVariants(id, p, v);
        uint8 field = selector % 8;
        if (field == 0) p[0].invariantPcrPolicy.pcrSpecs256[0].comparison = abi.encode(mutation);
        if (field == 1) p[0].attributes[0].value ^= mutation;
        if (field == 2) p[0].pcrBankSelection = PcrBankSelection.Sha384;
        if (field == 3) p[0].name = "different-parent";
        if (field == 4) v[0][0].variantPcrPolicy.pcrSpecs256[0].comparison = abi.encode(mutation);
        if (field == 5) v[0][0].attributes[0].value ^= mutation;
        if (field == 6) v[0][0].name = "different-machine";
        if (field == 7) s.version = "other-image-id";
        bytes32 digest = _variantDigest(_imageId(s), p[0], v[0][0]);
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidVariantSignature.selector, digest, LibKey.computeKeyFingerprint(imageOwner)
            )
        );
        _publish(s, p, v, sigs);
    }

    function testOuterSignatureBindsSignatureMatrix() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes[][] memory sigs = _signVariants(_imageId(s), p, v);
        bytes memory outer = _sign(
            IMAGE_KEY,
            sha256(abi.encode(BASEIMAGE_REGISTER_MSG_V2, block.chainid, address(images), deadline, s, p, v, sigs))
        );
        sigs[0][0] = hex"01";
        bytes32 altered =
            sha256(abi.encode(BASEIMAGE_REGISTER_MSG_V2, block.chainid, address(images), deadline, s, p, v, sigs));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidSignature.selector, altered, LibKey.computeKeyFingerprint(imageOwner)
            )
        );
        images.registerBaseImageV2(s, p, v, sigs, deadline, imageOwner, outer);
    }

    function testRejectsMissingSignatureRowsAndColumns() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes[][] memory sigs = new bytes[][](1);
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.VariantSignatureArrayLengthMismatch.selector, uint256(2), uint256(1)
            )
        );
        _publish(s, p, v, sigs);
        sigs = new bytes[][](2);
        sigs[0] = new bytes[](0);
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.VariantSignatureArrayLengthMismatch.selector, uint256(2), uint256(0)
            )
        );
        _publish(s, p, v, sigs);
    }

    function testRejectsEmptyInnerSignature() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes32 id = _imageId(s);
        bytes[][] memory sigs = _signVariants(id, p, v);
        sigs[0][0] = "";
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidVariantSignature.selector,
                _variantDigest(id, p[0], v[0][0]),
                LibKey.computeKeyFingerprint(imageOwner)
            )
        );
        _publish(s, p, v, sigs);
    }

    function testAddCannotChangeParentOrOverwriteVariantAndRollsBackSignatureWrites() public {
        (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _registered();
        bytes32 pid = _profileId(id, p[0]);
        bytes32 vid = _variantId(pid, v[0][0]);
        bytes memory original = images.getSignedVariant(id, pid, vid).variantSignature;
        v[0][0].attributes[0].value = bytes32(uint256(99));
        bytes[][] memory sigs = _signVariants(id, p, v);
        _expectContractRevert(abi.encodeWithSelector(BaseImageRegistry.MeasurementVariantAlreadyExists.selector, vid));
        _append(id, p, v, sigs);
        assertEq(images.getSignedVariant(id, pid, vid).variantSignature, original);
        p[0].attributes[0].value = bytes32(uint256(99));
        sigs = _signVariants(id, p, v);
        _expectContractRevert(abi.encodeWithSelector(BaseImageRegistry.PlatformProfileMetadataMismatch.selector, pid));
        _append(id, p, v, sigs);
        assertEq(images.getSignedVariant(id, pid, vid).variantSignature, original);
    }

    function testNewVariantCannotOverrideInvariant() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes32 id = _imageId(s);
        v[0][0].variantPcrPolicy.pcrSpecs256[0].pcrIndex = 4;
        bytes[][] memory sigs = _signVariants(id, p, v);
        _expectContractRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.VariantOverridesInvariantPcr.selector, _profileId(id, p[0]), uint8(4)
            )
        );
        _publish(s, p, v, sigs);
    }

    function testGetterRejectsCrossedHierarchy() public {
        (bytes32 id, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _registered();
        bytes32 pid = _profileId(id, p[0]);
        bytes32 wrong = _variantId(_profileId(id, p[1]), v[1][0]);
        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.HierarchyMismatch.selector, id, pid, wrong));
        images.getSignedVariant(id, pid, wrong);
    }

    function testLegacyImageRegistrationAndAdditionRemainSupported() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes memory outer = _sign(
            IMAGE_KEY, sha256(abi.encode(BASEIMAGE_REGISTER_MSG, block.chainid, address(images), deadline, s, p, v))
        );
        bytes32 id = images.registerBaseImage(s, p, v, deadline, imageOwner, outer);
        bytes32 pid = _profileId(id, p[0]);
        bytes32 vid = _variantId(pid, v[0][0]);
        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.VariantSignatureUnavailable.selector, vid));
        images.getSignedVariant(id, pid, vid);
        v[0][0].name = "legacy-added-1";
        v[0][1].name = "legacy-added-2";
        v[1][0].name = "legacy-added-3";
        outer = _sign(
            IMAGE_KEY, sha256(abi.encode(BASEIMAGE_UPDATE_MSG, block.chainid, address(images), deadline, id, p, v))
        );
        images.addPlatformVariants(id, p, v, deadline, imageOwner, outer);
        images.getVariant(id, pid, _variantId(pid, v[0][0]));
        v[0][0].name = "v2-added-1";
        v[0][1].name = "v2-added-2";
        v[1][0].name = "v2-added-3";
        _append(id, p, v, _signVariants(id, p, v));
        images.getSignedVariant(id, pid, _variantId(pid, v[0][0]));
    }

    function _workload(bytes32 imageId) internal pure virtual returns (WorkloadSpec memory s) {
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = imageId;
        AttributeRequirement[] memory requirements = new AttributeRequirement[](1);
        bytes32[] memory values = new bytes32[](1);
        values[0] = bytes32(uint256(1));
        requirements[0] = AttributeRequirement(keccak256("cloud"), values);
        return WorkloadSpec(
            "independent-workload-publisher",
            "v0.3.5-debug",
            3600,
            AccessMode.WHITELIST,
            ids,
            requirements,
            _pcr(23, bytes32(uint256(77)))
        );
    }

    function _workloadId(WorkloadSpec memory s) internal view returns (bytes32) {
        return keccak256(abi.encode(WORKLOAD_DOMAIN, LibKey.computeKeyFingerprint(workloadOwner), s.name, s.version));
    }

    function _workloadSig(WorkloadSpec memory s) internal view returns (bytes memory) {
        return _sign(WORKLOAD_KEY, sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, _workloadId(s), s)));
    }

    function _publishWorkload(WorkloadSpec memory s, bytes memory inner) internal returns (bytes32) {
        bytes memory outer = _sign(
            WORKLOAD_KEY,
            sha256(abi.encode(WORKLOAD_REGISTER_MSG_V2, block.chainid, address(workloads), deadline, s, inner))
        );
        _expectNextRegistryCall();
        return workloads.registerWorkloadV2(s, inner, deadline, workloadOwner, outer);
    }

    function testDifferentWorkloadAndImagePublishersVerifyAfterDeadline() public {
        (bytes32 imageId,,) = _registered();
        WorkloadSpec memory s = _workload(imageId);
        bytes32 wid = _publishWorkload(s, _workloadSig(s));
        assertTrue(workloads.isBaseImageAllowed(wid, imageId));
        assertFalse(workloads.isBaseImageAllowed(wid, bytes32(uint256(1))));
        vm.warp(deadline + 1);
        vm.chainId(987654);
        SignedWorkload memory r = workloads.getSignedWorkload(wid);
        assertTrue(r.ownerFingerprint != LibKey.computeKeyFingerprint(imageOwner));
        assertEq(r.ownerFingerprint, LibKey.computeKeyFingerprint(r.ownerIdentity));
        assertTrue(
            verifier.verify(
                r.ownerIdentity, sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, wid, r.spec)), r.workloadSignature
            )
        );
        assertEq(abi.encode(workloads.getWorkload(wid)), abi.encode(r.spec));
        assertEq(
            PublisherPolicy.workloadDigest(wid, r.spec),
            sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, wid, r.spec))
        );
    }

    function testFuzzWorkloadSignatureBindsFullSpec(uint8 selector) public {
        WorkloadSpec memory s = _workload(bytes32(uint256(1)));
        bytes memory inner = _workloadSig(s);
        uint8 field = selector % 7;
        if (field == 0) s.name = "different";
        if (field == 1) s.version = "different";
        if (field == 2) s.sessionTtl++;
        if (field == 3) s.baseImageMode = AccessMode.ANY;
        if (field == 4) s.baseImageIds[0] = bytes32(uint256(2));
        if (field == 5) s.requirements[0].allowedValues[0] = bytes32(uint256(2));
        if (field == 6) {
            s.workloadPcrPolicy.pcrSpecs256[0].comparison = PcrComparison.encodeStatic256(bytes32(uint256(88)));
        }
        _expectContractRevert(
            abi.encodeWithSelector(
                WorkloadRegistry.InvalidWorkloadSignature.selector,
                sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, _workloadId(s), s)),
                LibKey.computeKeyFingerprint(workloadOwner)
            )
        );
        _publishWorkload(s, inner);
    }

    function testWorkloadRejectsOtherPublisherAndEmptySignatures() public {
        WorkloadSpec memory s = _workload(bytes32(uint256(1)));
        bytes32 digest = sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, _workloadId(s), s));
        bytes memory wrong = _sign(IMAGE_KEY, digest);
        _expectContractRevert(
            abi.encodeWithSelector(
                WorkloadRegistry.InvalidWorkloadSignature.selector, digest, LibKey.computeKeyFingerprint(workloadOwner)
            )
        );
        _publishWorkload(s, wrong);
        _expectContractRevert(
            abi.encodeWithSelector(
                WorkloadRegistry.InvalidWorkloadSignature.selector, digest, LibKey.computeKeyFingerprint(workloadOwner)
            )
        );
        _publishWorkload(s, "");
    }

    function testWorkloadOuterSignatureBindsInnerSignature() public {
        WorkloadSpec memory s = _workload(bytes32(uint256(1)));
        bytes memory inner = _workloadSig(s);
        bytes memory outer = _sign(
            WORKLOAD_KEY,
            sha256(abi.encode(WORKLOAD_REGISTER_MSG_V2, block.chainid, address(workloads), deadline, s, inner))
        );
        inner = hex"01";
        vm.expectRevert(
            abi.encodeWithSelector(
                WorkloadRegistry.InvalidSignature.selector,
                sha256(abi.encode(WORKLOAD_REGISTER_MSG_V2, block.chainid, address(workloads), deadline, s, inner)),
                LibKey.computeKeyFingerprint(workloadOwner)
            )
        );
        workloads.registerWorkloadV2(s, inner, deadline, workloadOwner, outer);
    }

    function testLegacyWorkloadStillWorksButDoesNotClaimDurableSignature() public {
        WorkloadSpec memory s = _workload(bytes32(uint256(1)));
        bytes memory outer = _sign(
            WORKLOAD_KEY, sha256(abi.encode(WORKLOAD_REGISTER_MSG, block.chainid, address(workloads), deadline, s))
        );
        bytes32 wid = workloads.registerWorkload(s, deadline, workloadOwner, outer);
        assertEq(abi.encode(workloads.getWorkload(wid)), abi.encode(s));
        vm.expectRevert(abi.encodeWithSelector(WorkloadRegistry.WorkloadSignatureUnavailable.selector, wid));
        workloads.getSignedWorkload(wid);
    }

    function testV1PublicationSignatureCannotAuthorizeV2() public {
        (BaseImageSpec memory s, PlatformProfile[] memory p, MeasurementVariant[][] memory v) = _data();
        bytes[][] memory sigs = _signVariants(_imageId(s), p, v);
        bytes memory legacy = _sign(
            IMAGE_KEY, sha256(abi.encode(BASEIMAGE_REGISTER_MSG, block.chainid, address(images), deadline, s, p, v))
        );
        bytes32 digest =
            sha256(abi.encode(BASEIMAGE_REGISTER_MSG_V2, block.chainid, address(images), deadline, s, p, v, sigs));
        vm.expectRevert(
            abi.encodeWithSelector(
                BaseImageRegistry.InvalidSignature.selector, digest, LibKey.computeKeyFingerprint(imageOwner)
            )
        );
        images.registerBaseImageV2(s, p, v, sigs, deadline, imageOwner, legacy);
    }
}
