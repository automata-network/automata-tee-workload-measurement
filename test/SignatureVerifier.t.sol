// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {PublicIdentity} from "../src/types/Common.sol";
import {ALGO_ID_RS256, ALGO_ID_ES256, ALGO_ID_ES256K} from "../src/types/Constants.sol";
import {TestSetup} from "./utils/TestSetup.sol";

contract SignatureVerifierTest is TestSetup {
    uint256 private constant PRIVATE_KEY = 0xA11CE;

    SignatureVerifier private verifier;
    PublicIdentity private identity;
    PublicIdentity private p256Identity;

    function setUp() public override {
        super.setUp();
        verifier = new SignatureVerifier(P256_VERIFIER);
        identity = PublicIdentity({
            typeId: ALGO_ID_ES256K,
            key: hex"04a64db41e2968c849c2a5615ba0d6e816734a6d3e6ea6ecd6f3acb7d59daa9102e7af12d6e07238e7d5f5f6e9d6a529833a30f7385075fd74029db8009a5ace9a"
        });
        p256Identity = PublicIdentity({
            typeId: ALGO_ID_ES256,
            key: hex"0411726097cdeffa8d5054048530ca06a0461ff196f389e3586e09eead5d08607658ab16f51081daaadc9ac3c2e7c2539e718e9af371811d0f5b37f064d1634038"
        });
    }

    function testEs256kAcceptsValidSignature() public {
        bytes32 message = keccak256("valid signature");
        bytes memory signature = _sign(message);

        assertTrue(verifier.verify(identity, message, signature));
    }

    function testEs256kRejectsWrongMessageAndWrongKey() public {
        bytes32 message = keccak256("signed message");
        bytes memory signature = _sign(message);
        assertFalse(verifier.verify(identity, keccak256("different message"), signature));

        PublicIdentity memory wrongIdentity = PublicIdentity({
            typeId: ALGO_ID_ES256K,
            key: hex"045d45cb81aa765d69ca52e3869491ecf0e8fdf6a63d64e65b5213647ee4973ae5a4a4a32b51a76d77773517e7c103a7dcfdab36fe3cafa2bdb17f82b12fd019db"
        });
        assertFalse(verifier.verify(wrongIdentity, message, signature));
    }

    function testEs256kRejectsMalformedPublicKey() public view {
        PublicIdentity memory malformed = PublicIdentity({typeId: ALGO_ID_ES256K, key: new bytes(64)});
        assertFalse(verifier.verify(malformed, keccak256("message"), new bytes(65)));
    }

    function testEs256kRejectsMathematicallyEquivalentHighSSignature() public view {
        bytes32 message = keccak256("high-s signature");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, message);
        bytes32 highS = bytes32(SECP256K1_ORDER - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory highSignature = abi.encodePacked(r, highS, flippedV);

        assertFalse(verifier.verify(identity, message, highSignature));
    }

    function testEs256AcceptsLowSAndEquivalentHighSSignatures() public view {
        bytes32 message = 0x562165947737f3447d436cb1b93c45e1b08fa6d834c40e7072243ef324481e7c;
        bytes memory lowSignature =
            hex"304402207d3f6fdc6b301c90ab9fb1a9f1e4267faa143e17ad8b3ee6125f1634c3babe340220111b8007bc438760cad46b949da095c0a3178fc754982833f191db2482b67a32";
        bytes memory highSignature =
            hex"304502207d3f6fdc6b301c90ab9fb1a9f1e4267faa143e17ad8b3ee6125f1634c3babe34022100eee47ff743bc78a0352b946b625f6a3f19cf6ae6527f76510227ef9e79acab1f";

        assertTrue(verifier.verify(p256Identity, message, lowSignature));
        assertTrue(verifier.verify(p256Identity, message, highSignature));
        assertFalse(verifier.verify(p256Identity, keccak256("different message"), lowSignature));
    }

    /// @dev Builds a DER-encoded PKCS#1 RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e })
    ///      with a 256-byte modulus whose top bit is clear (no leading-zero padding).
    function _rsaKey(bytes memory exponent) private pure returns (bytes memory) {
        bytes memory n = new bytes(256);
        n[0] = 0x01;
        return abi.encodePacked(
            bytes2(0x3082), // SEQUENCE, long-form length (2 bytes follow)
            uint16(260 + 2 + exponent.length), // content: INTEGER n TLV + INTEGER e TLV
            bytes2(0x0282), // INTEGER, long-form length
            uint16(256),
            n,
            bytes1(0x02), // INTEGER
            bytes1(uint8(exponent.length)),
            exponent
        );
    }

    /// @dev FIPS 186-4/186-5 §B.3.1: the RSA public exponent must be an odd integer with
    ///      2^16 < e < 2^256. DER decoding strips leading zero bytes, so the check applies
    ///      to the decoded integer value, not the encoding.
    function testRs256RejectsNonFipsExponents() public {
        bytes32 message = keccak256("rsa exponent");
        bytes memory signature = new bytes(256);

        // e = 1: modular exponentiation degenerates to the identity operation.
        PublicIdentity memory e1 = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"01")});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, hex"01"));
        verifier.verify(e1, message, signature);

        // e = 3: odd but below the FIPS lower bound of 2^16.
        PublicIdentity memory e3 = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"03")});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, hex"03"));
        verifier.verify(e3, message, signature);

        // e = 17: another real-world exponent, still below the bound.
        PublicIdentity memory e17 = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"11")});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, hex"11"));
        verifier.verify(e17, message, signature);

        // e = 65536 (2^16): the bound itself, excluded by FIPS (and even).
        PublicIdentity memory e65536 = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"010000")});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, hex"010000"));
        verifier.verify(e65536, message, signature);

        // e = 16777472: even exponents are mathematically invalid for RSA.
        PublicIdentity memory even = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"01010000")});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, hex"01010000"));
        verifier.verify(even, message, signature);

        // A 33-byte odd exponent exceeds the FIPS upper bound of 2^256.
        bytes memory eOversized = new bytes(33);
        eOversized[0] = 0x01;
        eOversized[32] = 0x01;
        PublicIdentity memory oversized = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(eOversized)});
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.InvalidRsaExponent.selector, eOversized));
        verifier.verify(oversized, message, signature);
    }

    function testRs256AcceptsFipsCompliantExponents() public view {
        // A wrong signature returns false; the exponent check must not revert.

        // The standard exponent 65537, used by TPM AKs and MAA signing keys.
        PublicIdentity memory standard = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"010001")});
        assertFalse(verifier.verify(standard, keccak256("rsa exponent"), new bytes(256)));

        // 65539: any odd exponent above 2^16 is FIPS-compliant.
        PublicIdentity memory other = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(hex"010003")});
        assertFalse(verifier.verify(other, keccak256("rsa exponent"), new bytes(256)));

        // A 32-byte odd exponent is the largest still below 2^256.
        bytes memory eMax = new bytes(32);
        eMax[0] = 0x01;
        eMax[31] = 0x01;
        PublicIdentity memory maximal = PublicIdentity({typeId: ALGO_ID_RS256, key: _rsaKey(eMax)});
        assertFalse(verifier.verify(maximal, keccak256("rsa exponent"), new bytes(256)));
    }

    function _sign(bytes32 message) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, message);
        return abi.encodePacked(r, s, v);
    }
}
