// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {MaaKeyRegistry} from "../src/MaaKeyRegistry.sol";
import {IMaaKeyRegistry, MaaSigningKey} from "../src/interfaces/registries/IMaaKeyRegistry.sol";

/// @title MaaKeyRegistryTest
/// @notice Admin-surface tests for the MaaKeyRegistry — exercises upsert, revoke, view, and
///         the validation rejections. Authentication is via OwnableUpgradeable's onlyOwner;
///         non-owner calls revert OwnableUnauthorizedAccount.
contract MaaKeyRegistryTest is Test {
    MaaKeyRegistry internal registry;

    address internal constant owner = address(0xABCD);
    address internal constant rando = address(0xDEAD);

    bytes32 internal constant TEST_KID_HASH = keccak256(bytes("test-kid"));
    bytes internal constant TEST_PKCS1_PUBKEY = hex"30820122300d06092a864886f70d01010105000382010f00";
    bytes32 internal constant TEST_ISSUER_HASH = keccak256(bytes("https://sharedeus.eus.attest.azure.net"));

    function setUp() public {
        vm.startPrank(owner);
        MaaKeyRegistry impl = new MaaKeyRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(MaaKeyRegistry.initialize, (owner)));
        registry = MaaKeyRegistry(address(proxy));
        vm.stopPrank();
    }

    function test_upsert_then_get_round_trip() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IMaaKeyRegistry.MaaSigningKeyUpserted(TEST_KID_HASH, TEST_ISSUER_HASH, notAfter);

        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertEq(stored.pkcs1Pubkey, TEST_PKCS1_PUBKEY, "pkcs1Pubkey mismatch");
        assertEq(stored.issuerHash, TEST_ISSUER_HASH, "issuerHash mismatch");
        assertEq(stored.notAfter, notAfter, "notAfter mismatch");
        assertEq(stored.revoked, false, "revoked default mismatch");
        assertTrue(registry.hasMaaSigningKey(TEST_KID_HASH));
    }

    function test_revoke_marks_key_and_disables_hasMaaSigningKey() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);

        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IMaaKeyRegistry.MaaSigningKeyRevoked(TEST_KID_HASH);

        vm.prank(owner);
        registry.revokeMaaSigningKey(TEST_KID_HASH);

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertTrue(stored.revoked, "should be revoked");
        assertFalse(registry.hasMaaSigningKey(TEST_KID_HASH));
    }

    function test_upsert_replaces_existing_key_and_resets_revoked() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);

        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);

        vm.prank(owner);
        registry.revokeMaaSigningKey(TEST_KID_HASH);
        assertTrue(registry.getMaaSigningKey(TEST_KID_HASH).revoked);

        bytes memory replacementPubkey = hex"30820122300d06092a864886f70d01010105000382010f00aabb";
        bytes32 newIssuer = keccak256(bytes("https://sharedcus.cus.attest.azure.net"));
        uint64 newNotAfter = uint64(block.timestamp + 730 days);

        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, replacementPubkey, newIssuer, newNotAfter);

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertEq(stored.pkcs1Pubkey, replacementPubkey, "pubkey not replaced");
        assertEq(stored.issuerHash, newIssuer, "issuer not replaced");
        assertEq(stored.notAfter, newNotAfter, "notAfter not replaced");
        assertEq(stored.revoked, false, "revoked must reset on upsert");
    }

    function test_upsert_at_notAfter_boundary_accepted() public {
        // notAfter exactly equal to block.timestamp must be accepted on upsert —
        // matches the on-chain verifier which accepts block.timestamp <= notAfter.
        uint64 notAfter = uint64(block.timestamp);

        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);
        assertTrue(registry.hasMaaSigningKey(TEST_KID_HASH));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Rejections
    // ────────────────────────────────────────────────────────────────────────

    function test_revert_when_non_owner_upserts() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, rando));
        vm.prank(rando);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);
    }

    function test_revert_when_non_owner_revokes() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter);

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, rando));
        vm.prank(rando);
        registry.revokeMaaSigningKey(TEST_KID_HASH);
    }

    function test_revert_when_pubkey_empty() public {
        vm.expectRevert(MaaKeyRegistry.EmptyPubkey.selector);
        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, hex"", TEST_ISSUER_HASH, uint64(block.timestamp + 1));
    }

    function test_revert_when_issuer_hash_zero() public {
        vm.expectRevert(MaaKeyRegistry.EmptyIssuerHash.selector);
        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, bytes32(0), uint64(block.timestamp + 1));
    }

    function test_revert_when_notAfter_in_past() public {
        // notAfter strictly less than block.timestamp reverts; equality is allowed
        // (covered by test_upsert_at_notAfter_boundary_accepted).
        vm.warp(100);
        vm.expectPartialRevert(MaaKeyRegistry.NotAfterInPast.selector);
        vm.prank(owner);
        registry.upsertMaaSigningKey(TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, uint64(99));
    }

    function test_revert_when_revoking_unregistered_kid() public {
        vm.expectPartialRevert(MaaKeyRegistry.KidNotRegistered.selector);
        vm.prank(owner);
        registry.revokeMaaSigningKey(keccak256(bytes("never-registered")));
    }

    function test_unregistered_kid_returns_empty_struct() public view {
        MaaSigningKey memory stored = registry.getMaaSigningKey(keccak256(bytes("nope")));
        assertEq(stored.pkcs1Pubkey.length, 0);
        assertEq(stored.issuerHash, bytes32(0));
        assertEq(stored.notAfter, 0);
        assertFalse(stored.revoked);
        assertFalse(registry.hasMaaSigningKey(keccak256(bytes("nope"))));
    }
}
