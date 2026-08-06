// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
import {
    AccessMode,
    AttributeRequirement,
    PcrPolicyBlock,
    PcrSpec256,
    PcrSpec384,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";

/// @notice Base-image access-mode validation at workload registration.
contract WorkloadRegistryTest is Test {
    WorkloadRegistry private registry;
    PublicIdentity private ownerIdentity;

    function setUp() public {
        registry = new WorkloadRegistry(new MockSignatureVerifier());
        ownerIdentity = PublicIdentity({typeId: 2, key: hex"1234"});
    }

    /// @dev An empty whitelist denies every base image, so no session could ever reference the
    ///      workload. Registration is one-shot and the name/version pair stays claimed, so the
    ///      mistake would be unrecoverable under that identifier.
    function testRejectsWhitelistModeWithEmptyBaseImageSet() public {
        vm.expectRevert(WorkloadRegistry.EmptyBaseImageWhitelist.selector);
        registry.registerWorkload(
            _spec("empty-whitelist", AccessMode.WHITELIST, new bytes32[](0)),
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );
    }

    function testAcceptsWhitelistModeWithNonEmptyBaseImageSet() public {
        bytes32[] memory allowed = new bytes32[](1);
        allowed[0] = keccak256("base-image");

        bytes32 workloadId = registry.registerWorkload(
            _spec("populated-whitelist", AccessMode.WHITELIST, allowed),
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );

        assertTrue(registry.isBaseImageAllowed(workloadId, allowed[0]));
        assertFalse(registry.isBaseImageAllowed(workloadId, keccak256("other")));
    }

    /// @dev Only WHITELIST is constrained. An empty BLACKLIST blocks nothing and an empty
    ///      baseImageIds set under ANY is ignored; both leave a usable workload.
    function testAcceptsEmptyBaseImageSetForOtherModes() public {
        bytes32 blacklisted = registry.registerWorkload(
            _spec("empty-blacklist", AccessMode.BLACKLIST, new bytes32[](0)),
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );
        assertTrue(registry.isBaseImageAllowed(blacklisted, keccak256("anything")));

        bytes32 unrestricted = registry.registerWorkload(
            _spec("any-mode", AccessMode.ANY, new bytes32[](0)),
            uint64(block.timestamp + 1 hours),
            ownerIdentity,
            hex"01"
        );
        assertTrue(registry.isBaseImageAllowed(unrestricted, keccak256("anything")));
    }

    function _spec(string memory name, AccessMode mode, bytes32[] memory baseImageIds)
        private
        pure
        returns (WorkloadSpec memory)
    {
        return WorkloadSpec({
            name: name,
            version: "1.0.0",
            sessionTtl: 1 days,
            baseImageMode: mode,
            baseImageIds: baseImageIds,
            requirements: new AttributeRequirement[](0),
            workloadPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)})
        });
    }
}
