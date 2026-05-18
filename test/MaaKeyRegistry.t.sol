// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {MaaKeyRegistry} from "../src/MaaKeyRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IMaaKeyRegistry, MaaSigningKey} from "../src/interfaces/registries/IMaaKeyRegistry.sol";
import {PublicIdentity} from "../src/types/Common.sol";
import {ALGO_ID_ES256K, MAA_KEY_UPSERT_MSG, MAA_KEY_REVOKE_MSG} from "../src/types/Constants.sol";

/// @title MaaKeyRegistryTest
/// @notice Admin-surface tests for the MaaKeyRegistry — exercises upsert, revoke, view, and
///         the validation rejections without engineering a real MAA JWT fixture (the on-chain
///         JWT verification logic is exercised via AkCollateralVerifier in a separate harness,
///         once a synthetic JWT fixture is added).
contract MaaKeyRegistryTest is Test {
    SignatureVerifier internal signatureVerifier;
    MaaKeyRegistry internal registry;

    address internal constant owner = address(0xABCD);
    PublicIdentity internal ownerIdentity;

    bytes32 internal constant TEST_KID_HASH = keccak256(bytes("test-kid"));
    bytes internal constant TEST_PKCS1_PUBKEY = hex"30820122300d06092a864886f70d01010105000382010f00";
    bytes32 internal constant TEST_ISSUER_HASH = keccak256(bytes("https://sharedeus.eus.attest.azure.net"));

    function setUp() public {
        ownerIdentity = PublicIdentity({typeId: ALGO_ID_ES256K, key: hex"04aabbccdd"});

        vm.startPrank(owner);
        signatureVerifier = new SignatureVerifier(address(0xdead));
        MaaKeyRegistry impl = new MaaKeyRegistry(signatureVerifier);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(MaaKeyRegistry.initialize, (owner)));
        registry = MaaKeyRegistry(address(proxy));
        vm.stopPrank();

        // SignatureVerifier.verify is mocked to true throughout — these tests target the
        // admin-surface invariants, not signature validity.
        vm.mockCall(
            address(signatureVerifier), abi.encodeWithSelector(signatureVerifier.verify.selector), abi.encode(true)
        );
    }

    function test_upsert_then_get_round_trip() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IMaaKeyRegistry.MaaSigningKeyUpserted(TEST_KID_HASH, TEST_ISSUER_HASH, notAfter);

        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertEq(stored.pkcs1Pubkey, TEST_PKCS1_PUBKEY, "pkcs1Pubkey mismatch");
        assertEq(stored.issuerHash, TEST_ISSUER_HASH, "issuerHash mismatch");
        assertEq(stored.notAfter, notAfter, "notAfter mismatch");
        assertEq(stored.revoked, false, "revoked default mismatch");
        assertTrue(registry.hasMaaSigningKey(TEST_KID_HASH));
    }

    function test_revoke_marks_key_and_disables_hasMaaSigningKey() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );

        vm.expectEmit(true, false, false, true, address(registry));
        emit IMaaKeyRegistry.MaaSigningKeyRevoked(TEST_KID_HASH);

        registry.revokeMaaSigningKey(TEST_KID_HASH, expireAt, ownerIdentity, hex"00");

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertTrue(stored.revoked, "should be revoked");
        // hasMaaSigningKey returns false for revoked keys
        assertFalse(registry.hasMaaSigningKey(TEST_KID_HASH));
    }

    function test_upsert_replaces_existing_key() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );

        bytes memory replacementPubkey = hex"30820122300d06092a864886f70d01010105000382010f00aabb";
        bytes32 newIssuer = keccak256(bytes("https://sharedcus.cus.attest.azure.net"));
        uint64 newNotAfter = uint64(block.timestamp + 730 days);

        registry.upsertMaaSigningKey(
            TEST_KID_HASH, replacementPubkey, newIssuer, newNotAfter, expireAt, ownerIdentity, hex"00"
        );

        MaaSigningKey memory stored = registry.getMaaSigningKey(TEST_KID_HASH);
        assertEq(stored.pkcs1Pubkey, replacementPubkey, "pubkey not replaced");
        assertEq(stored.issuerHash, newIssuer, "issuer not replaced");
        assertEq(stored.notAfter, newNotAfter, "notAfter not replaced");
        assertEq(stored.revoked, false, "revoked flag should reset on upsert");
    }

    function test_revert_when_signature_expired() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        // expireAt before now
        uint64 expireAt = uint64(block.timestamp - 1);

        vm.expectRevert(MaaKeyRegistry.SignatureExpired.selector);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );
    }

    function test_revert_when_pubkey_empty() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        vm.expectRevert(MaaKeyRegistry.EmptyPubkey.selector);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, hex"", TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );
    }

    function test_revert_when_issuer_hash_zero() public {
        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        vm.expectRevert(MaaKeyRegistry.EmptyIssuerHash.selector);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, bytes32(0), notAfter, expireAt, ownerIdentity, hex"00"
        );
    }

    function test_revert_when_notAfter_in_past() public {
        uint64 notAfter = uint64(block.timestamp); // not strictly greater than block.timestamp
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        vm.expectRevert(MaaKeyRegistry.NotAfterInPast.selector);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );
    }

    function test_revert_when_owner_signature_invalid() public {
        // Override the global mock to return false for this test only.
        vm.mockCall(
            address(signatureVerifier), abi.encodeWithSelector(signatureVerifier.verify.selector), abi.encode(false)
        );

        uint64 notAfter = uint64(block.timestamp + 365 days);
        uint64 expireAt = uint64(block.timestamp + 1 hours);

        vm.expectRevert(MaaKeyRegistry.InvalidSignature.selector);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, notAfter, expireAt, ownerIdentity, hex"00"
        );
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
