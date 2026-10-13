// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {PublisherSignaturesTest} from "./PublisherSignatures.t.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    WorkloadSpec,
    ResolvedPcrPolicy
} from "../src/types/Common.sol";

/// @notice Runs real-signature cases against upgraded proxies inherited from Hoodi.
/// @dev Opt in with HOODI_FORK_RPC and HOODI_FORK_SESSION_REGISTRY. Never broadcasts.
contract PublisherSignaturesForkTest is PublisherSignaturesTest {
    SessionRegistry private sessions;
    bytes32 private constant LEGACY_IMAGE = 0xdc22f0710de7d5da51dca3a3e1ad39d63f0bf00289b4f0562b041dc204baf5df;
    bytes32 private constant LEGACY_WORKLOAD = 0x0769200371cf130265bb9121321cc5215ef0700f15c311b5ab64726acb029ca7;
    bytes32 private constant LEGACY_SESSION = 0x8813b9c3f49dc93c8b3aa1a238c8920850598fddd79c58502f8b74b87fbfdc7b;

    // Keep local test identities separate from the records broadcast by the rehearsal.
    function _data()
        internal
        pure
        override
        returns (BaseImageSpec memory spec, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants)
    {
        (spec, profiles, variants) = super._data();
        spec.name = "publisher-signature-fork-test";
    }

    function _workload(bytes32 imageId) internal pure override returns (WorkloadSpec memory spec) {
        spec = super._workload(imageId);
        spec.name = "independent-fork-workload-publisher";
    }

    function setUp() public override {
        string memory rpc = vm.envOr("HOODI_FORK_RPC", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        // Pin all tests to one block so they share cached account and storage reads.
        vm.createSelectFork(rpc, vm.envUint("HOODI_FORK_BLOCK_NUMBER"));
        require(block.chainid == 31337, "only hoodi-fork");
        sessions = SessionRegistry(vm.envAddress("HOODI_FORK_SESSION_REGISTRY"));
        images = BaseImageRegistry(address(sessions.baseImageRegistry()));
        workloads = WorkloadRegistry(address(sessions.workloadRegistry()));
        verifier = SignatureVerifier(address(images.signatureVerifier()));
        require(address(workloads.signatureVerifier()) == address(verifier), "different signature verifiers");
        bytes32 beforeRecords = _legacyRecords();
        bytes32[50] memory imageSlots;
        bytes32[50] memory workloadSlots;
        for (uint256 i; i < 50; ++i) {
            imageSlots[i] = vm.load(address(images), bytes32(i));
            workloadSlots[i] = vm.load(address(workloads), bytes32(i));
        }
        address imageAdmin = images.owner();
        address workloadAdmin = workloads.owner();
        BaseImageRegistry nextImage = new BaseImageRegistry(verifier);
        WorkloadRegistry nextWorkload = new WorkloadRegistry(verifier);
        vm.prank(imageAdmin);
        images.upgradeToAndCall(address(nextImage), "");
        vm.prank(workloadAdmin);
        workloads.upgradeToAndCall(address(nextWorkload), "");
        assertEq(_legacyRecords(), beforeRecords, "legacy records changed");
        for (uint256 i; i < 50; ++i) {
            assertEq(vm.load(address(images), bytes32(i)), imageSlots[i], "image slot changed");
            assertEq(vm.load(address(workloads), bytes32(i)), workloadSlots[i], "workload slot changed");
        }
        assertEq(images.owner(), imageAdmin);
        assertEq(workloads.owner(), workloadAdmin);
        imageOwner = _identity(IMAGE_KEY);
        workloadOwner = _identity(WORKLOAD_KEY);
        bytes32[] memory fingerprints = new bytes32[](1);
        fingerprints[0] = LibKey.computeKeyFingerprint(imageOwner);
        vm.prank(imageAdmin);
        images.addToWhitelist(fingerprints);
        fingerprints[0] = LibKey.computeKeyFingerprint(workloadOwner);
        vm.prank(workloadAdmin);
        workloads.addToWhitelist(fingerprints);
        deadline = uint64(block.timestamp + 1 hours);
    }

    function _legacyRecords() private view returns (bytes32) {
        bytes memory records = abi.encode(
            images.getBaseImage(LEGACY_IMAGE),
            images.getBaseImageOwner(LEGACY_IMAGE),
            images.isBaseImageRevoked(LEGACY_IMAGE),
            workloads.getWorkload(LEGACY_WORKLOAD),
            workloads.getWorkloadOwner(LEGACY_WORKLOAD),
            workloads.isWorkloadRevoked(LEGACY_WORKLOAD),
            sessions.getSession(LEGACY_SESSION),
            sessions.getSessionOwner(LEGACY_SESSION)
        );
        bytes32[] memory profiles = images.getPlatformProfileIds(LEGACY_IMAGE);
        for (uint256 i; i < profiles.length; ++i) {
            bytes32[] memory variants = images.getMeasurementVariantIds(profiles[i]);
            for (uint256 j; j < variants.length; ++j) {
                records =
                    abi.encode(records, sessions.getPcrPolicy(LEGACY_WORKLOAD, LEGACY_IMAGE, profiles[i], variants[j]));
            }
        }
        return keccak256(records);
    }

    function testInheritedSessionRegistryReadsExactV2Policies() public {
        (bytes32 imageId, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants) = _registered();
        WorkloadSpec memory spec = _workload(imageId);
        bytes32 workloadId = _publishWorkload(spec, _workloadSig(spec));
        bytes32 pid = _profileId(imageId, profiles[0]);
        ResolvedPcrPolicy memory policy =
            sessions.getPcrPolicy(workloadId, imageId, pid, _variantId(pid, variants[0][0]));
        assertEq(policy.baseImageId, imageId);
        assertEq(policy.workloadId, workloadId);
        assertEq(abi.encode(policy.invariantPcrPolicy), abi.encode(profiles[0].invariantPcrPolicy));
        assertEq(abi.encode(policy.variantPcrPolicy), abi.encode(variants[0][0].variantPcrPolicy));
        assertEq(abi.encode(policy.workloadPcrPolicy), abi.encode(spec.workloadPcrPolicy));
    }
}
