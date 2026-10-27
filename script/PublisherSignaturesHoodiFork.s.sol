// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {console2} from "forge-std/console2.sol";
import {PublisherSignaturesTest} from "../test/PublisherSignatures.t.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {SignedBaseImageVariant} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {SignedWorkload} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    WorkloadSpec,
    ResolvedPcrPolicy
} from "../src/types/Common.sol";
import {WORKLOAD_POLICY_SIGNATURE_DOMAIN} from "../src/types/Constants.sol";

/// @notice Broadcast rehearsal using public test keys. ONLY for the controlled Hoodi fork.
/// @dev Reuses the real-signature test fixtures. The node must unlock the registry admin.
///      No hardware attestation is generated. Run verifyPublished() after broadcasting.
contract PublisherSignaturesHoodiFork is PublisherSignaturesTest {
    SessionRegistry private sessions;

    function setUp() public override {}

    function _connect() private {
        require(block.chainid == 31337, "only hoodi-fork");
        sessions = SessionRegistry(vm.envAddress("HOODI_FORK_SESSION_REGISTRY"));
        images = BaseImageRegistry(address(sessions.baseImageRegistry()));
        workloads = WorkloadRegistry(address(sessions.workloadRegistry()));
        verifier = SignatureVerifier(address(images.signatureVerifier()));
        require(address(workloads.signatureVerifier()) == address(verifier), "verifier mismatch");
        imageOwner = _identity(IMAGE_KEY);
        workloadOwner = _identity(WORKLOAD_KEY);
        deadline = uint64(block.timestamp + 1 hours);
    }

    function run() external {
        _connect();
        address admin = images.owner();
        require(workloads.owner() == admin, "different admins: use separate upgrade broadcasts");
        bytes32 previous = _legacyRecords();
        bool imagePaused = images.paused();
        bool workloadPaused = workloads.paused();
        vm.startBroadcast(admin);
        BaseImageRegistry nextImage = new BaseImageRegistry(verifier);
        WorkloadRegistry nextWorkload = new WorkloadRegistry(verifier);
        images.upgradeToAndCall(address(nextImage), "");
        workloads.upgradeToAndCall(address(nextWorkload), "");
        assertEq(_legacyRecords(), previous, "legacy records changed");
        bytes32[] memory fingerprints = new bytes32[](1);
        fingerprints[0] = LibKey.computeKeyFingerprint(imageOwner);
        require(!images.isWhitelisted(fingerprints[0]), "image test key already whitelisted");
        images.addToWhitelist(fingerprints);
        fingerprints[0] = LibKey.computeKeyFingerprint(workloadOwner);
        require(!workloads.isWhitelisted(fingerprints[0]), "workload test key already whitelisted");
        workloads.addToWhitelist(fingerprints);
        (bytes32 imageId, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants) = _registered();
        _renameForAppend(variants);
        _append(imageId, profiles, variants, _signVariants(imageId, profiles, variants));
        WorkloadSpec memory spec = _workload(imageId);
        bytes32 workloadId = _publishWorkload(spec, _workloadSig(spec));
        images.removeFromWhitelist(LibKey.computeKeyFingerprint(imageOwner));
        workloads.removeFromWhitelist(LibKey.computeKeyFingerprint(workloadOwner));
        vm.stopBroadcast();
        assertEq(images.owner(), admin);
        assertEq(workloads.owner(), admin);
        assertEq(images.paused(), imagePaused);
        assertEq(workloads.paused(), workloadPaused);
        assertEq(_legacyRecords(), previous, "legacy records changed after publishing");
        _verifyPublished();
        console2.log("BaseImageRegistry implementation", address(nextImage));
        console2.log("WorkloadRegistry implementation", address(nextWorkload));
        console2.log("baseImageId");
        console2.logBytes32(imageId);
        console2.log("workloadId");
        console2.logBytes32(workloadId);
    }

    function verifyPublished() external {
        _connect();
        _verifyPublished();
        require(!images.isWhitelisted(LibKey.computeKeyFingerprint(imageOwner)), "image test permission remains");
        require(
            !workloads.isWhitelisted(LibKey.computeKeyFingerprint(workloadOwner)), "workload test permission remains"
        );
        console2.log("Verified six signed variants, signed workload, and SessionRegistry PCR policy on hoodi-fork");
    }

    function _verifyPublished() private view {
        (BaseImageSpec memory imageSpec, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants) =
            _data();
        bytes32 imageId = _imageId(imageSpec);
        _verifyVariants(imageId, profiles, variants);
        bytes32 profileId = _profileId(imageId, profiles[0]);
        bytes32 variantId = _variantId(profileId, variants[0][0]);
        _renameForAppend(variants);
        _verifyVariants(imageId, profiles, variants);
        WorkloadSpec memory spec = _workload(imageId);
        bytes32 wid = _workloadId(spec);
        SignedWorkload memory w = workloads.getSignedWorkload(wid);
        assertEq(w.ownerFingerprint, LibKey.computeKeyFingerprint(workloadOwner));
        assertEq(w.ownerFingerprint, LibKey.computeKeyFingerprint(w.ownerIdentity));
        assertEq(abi.encode(w.spec), abi.encode(spec));
        require(
            verifier.verify(
                w.ownerIdentity, sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, wid, w.spec)), w.workloadSignature
            ),
            "workload signature"
        );
        ResolvedPcrPolicy memory policy = sessions.getPcrPolicy(wid, imageId, profileId, variantId);
        assertEq(abi.encode(policy.invariantPcrPolicy), abi.encode(profiles[0].invariantPcrPolicy));
        assertEq(abi.encode(policy.variantPcrPolicy), abi.encode(variants[0][0].variantPcrPolicy));
        assertEq(abi.encode(policy.workloadPcrPolicy), abi.encode(spec.workloadPcrPolicy));
    }

    function _verifyVariants(bytes32 id, PlatformProfile[] memory profiles, MeasurementVariant[][] memory variants)
        private
        view
    {
        for (uint256 i; i < profiles.length; ++i) {
            bytes32 pid = _profileId(id, profiles[i]);
            for (uint256 j; j < variants[i].length; ++j) {
                SignedBaseImageVariant memory r = images.getSignedVariant(id, pid, _variantId(pid, variants[i][j]));
                assertEq(r.ownerFingerprint, LibKey.computeKeyFingerprint(imageOwner));
                assertEq(r.ownerFingerprint, LibKey.computeKeyFingerprint(r.ownerIdentity));
                assertEq(abi.encode(r.platformProfile), abi.encode(profiles[i]));
                assertEq(abi.encode(r.measurementVariant), abi.encode(variants[i][j]));
                require(
                    verifier.verify(
                        r.ownerIdentity, _variantDigest(id, r.platformProfile, r.measurementVariant), r.variantSignature
                    ),
                    "variant signature"
                );
            }
        }
    }

    function _renameForAppend(MeasurementVariant[][] memory variants) private pure {
        variants[0][0].name = "m6a.2xlarge";
        variants[0][1].name = "m6a.4xlarge";
        variants[1][0].name = "c3-standard-8";
    }

    function _legacyRecords() private view returns (bytes32) {
        bytes32 imageId = 0xdc22f0710de7d5da51dca3a3e1ad39d63f0bf00289b4f0562b041dc204baf5df;
        bytes32 workloadId = 0x0769200371cf130265bb9121321cc5215ef0700f15c311b5ab64726acb029ca7;
        return keccak256(
            abi.encode(
                images.getBaseImage(imageId),
                images.getBaseImageOwner(imageId),
                images.isBaseImageRevoked(imageId),
                workloads.getWorkload(workloadId),
                workloads.getWorkloadOwner(workloadId),
                workloads.isWorkloadRevoked(workloadId),
                sessions.getSession(0x8813b9c3f49dc93c8b3aa1a238c8920850598fddd79c58502f8b74b87fbfdc7b)
            )
        );
    }
}
