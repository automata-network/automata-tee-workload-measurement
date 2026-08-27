// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "./types/Common.sol";
import {ALGO_ID_RS256, ALGO_ID_ES256, ALGO_ID_ES256K} from "./types/Constants.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {Asn1Decode, NodePtr} from "./lib/Asn1Decode.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title SignatureVerifier
/// @notice On-chain verification of cryptographic signatures against PublicIdentity keys
/// @dev Foundation of the owner-auth model - allows TEE-managed keys (RSA, ECDSA-P256, etc.)
///      to own registry entries directly without relying on msg.sender addresses
/// @dev this is an indepedent contract to be called by other contracts for signature verification
contract SignatureVerifier is ISignatureVerifier {
    using Asn1Decode for bytes;
    using NodePtr for uint256;

    string public constant SIGNATURE_VERIFIER_VERSION = "1.0.0";

    address public immutable P256_VERIFIER_ADDRESS;

    /// @notice Thrown when an unsupported algorithm type is provided
    error UnsupportedAlgorithm(uint8 typeId);

    /// @notice RSA public exponent violates the FIPS 186-4 §B.3.1 constraint (an odd integer
    ///         with 2^16 < e < 2^256). The degenerate e = 1 would make the RSA verification
    ///         equation an identity operation, allowing PKCS#1 v1.5 forgery without the
    ///         private key; even exponents are mathematically invalid for RSA.
    error InvalidRsaExponent(bytes exponent);

    /// @notice ECDSA r/s component is wider than 32 bytes after DER stripping
    error InputTooLong(uint256 length);

    constructor(address p256VerifierAddress) {
        P256_VERIFIER_ADDRESS = p256VerifierAddress;
    }

    function verify(PublicIdentity calldata identity, bytes32 message, bytes calldata signature)
        external
        view
        returns (bool valid)
    {
        uint8 typeId = identity.typeId;

        if (typeId == ALGO_ID_RS256) {
            return _verifyRsa(identity.key, message, signature);
        } else if (typeId == ALGO_ID_ES256) {
            return _verifyP256(identity.key, message, signature);
        } else if (typeId == ALGO_ID_ES256K) {
            return _verifySecp256k1(identity.key, message, signature);
        } else {
            revert UnsupportedAlgorithm(typeId);
        }
    }

    /// @dev Verifies RSA PKCS#1 v1.5 SHA-256 signature
    /// @param key DER-encoded PKCS#1 RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e })
    /// @param message Message digest
    /// @param signature Raw RSA signature bytes
    /// @return valid True if signature is valid
    function _verifyRsa(bytes calldata key, bytes32 message, bytes calldata signature)
        internal
        view
        returns (bool valid)
    {
        // Copy key from calldata to memory (Asn1Decode requires memory)
        bytes memory keyMem = key;

        // Parse DER structure: SEQUENCE { n, e }
        uint256 rootPtr = keyMem.root();
        uint256 nPtr = keyMem.firstChildOf(rootPtr);
        uint256 ePtr = keyMem.nextSiblingOf(nPtr);

        // Extract modulus (n) and exponent (e) as bytes
        bytes memory n = keyMem.uintBytesAt(nPtr);
        bytes memory e = keyMem.uintBytesAt(ePtr);

        // FIPS 186-4/186-5 §B.3.1: the public exponent must be an odd integer with
        // 2^16 < e < 2^256. DER decoding strips leading zero bytes, so e.length >= 3 plus
        // an odd low byte together enforce e >= 65537. The degenerate e = 1 would make
        // modular exponentiation an identity operation, so an attacker could construct a
        // valid PKCS#1 v1.5 signature without the private key. All RSA signature paths
        // (owner identities, TPM certified keys, MAA signing keys) flow through here.
        if (e.length < 3 || e.length > 32 || (uint8(e[e.length - 1]) & 1) == 0) {
            revert InvalidRsaExponent(e);
        }

        // Copy signature from calldata to memory (OZ RSA requires memory)
        bytes memory sigMem = signature;

        // Verify using OpenZeppelin RSA library
        return RSA.pkcs1Sha256(message, sigMem, e, n);
    }

    /// @dev Verifies ECDSA P-256 signature via external verifier contract
    /// @param key SEC1 uncompressed point (65 bytes: 0x04 || x || y)
    /// @param message Message digest
    /// @param signature DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
    /// @return valid True if signature is valid
    function _verifyP256(bytes calldata key, bytes32 message, bytes calldata signature)
        internal
        view
        returns (bool valid)
    {
        // P-256 TPM firmware may return either mathematically valid s value. The atakit
        // portal normalizes TPM-produced signatures to low-s before submission, but this
        // verifier still accepts high-s for compatibility with other existing producers.
        // Enforce low-s here only after every P-256 producer performs the same normalization.

        // Validate key format: must be 65 bytes starting with 0x04
        if (key.length != 65 || key[0] != 0x04) {
            return false;
        }

        // Extract x and y coordinates from uncompressed point
        bytes32 x = bytes32(key[1:33]);
        bytes32 y = bytes32(key[33:65]);

        // Parse DER signature to extract r and s
        (bytes32 r, bytes32 s) = _decodeDerEcdsaSignature(signature);

        // Call external P256 verifier via staticcall
        bytes memory args = abi.encode(message, r, s, x, y);
        (bool success, bytes memory ret) = P256_VERIFIER_ADDRESS.staticcall(args);

        if (!success || ret.length != 32) {
            return false;
        }

        // Decode return value: 1 = valid signature, 0 = invalid
        return abi.decode(ret, (uint256)) == 1;
    }

    /// @dev Verifies ECDSA secp256k1 signature via ecrecover
    /// @param key SEC1 uncompressed point (65 bytes: 0x04 || x || y)
    /// @param message Message digest
    /// @param signature Ethereum-style signature (65 bytes: r || s || v)
    /// @return valid True if signature is valid
    function _verifySecp256k1(bytes calldata key, bytes32 message, bytes calldata signature)
        internal
        pure
        returns (bool valid)
    {
        // Validate key format: must be 65 bytes starting with 0x04
        if (key.length != 65 || key[0] != 0x04) {
            return false;
        }

        // Derive expected address from public key
        // Skip first byte (0x04 prefix) and hash the x,y coordinates
        address expectedAddress = address(uint160(uint256(keccak256(key[1:65]))));

        // Recover signer address from signature (using calldata variant to avoid copy)
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(message, signature);

        // Valid only if recovery succeeded and address matches
        return err == ECDSA.RecoverError.NoError && recovered == expectedAddress;
    }

    /// @dev Parses DER-encoded ECDSA signature to extract r and s values
    /// @param signature DER-encoded signature (SEQUENCE { INTEGER r, INTEGER s })
    /// @return r The r component as bytes32
    /// @return s The s component as bytes32
    function _decodeDerEcdsaSignature(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s) {
        // Copy signature from calldata to memory (Asn1Decode requires memory)
        bytes memory sigMem = signature;

        // Parse DER structure: SEQUENCE { r, s }
        uint256 rootPtr = sigMem.root();
        uint256 rPtr = sigMem.firstChildOf(rootPtr);
        uint256 sPtr = sigMem.nextSiblingOf(rPtr);

        // Extract r and s as variable-length bytes, then convert to bytes32
        bytes memory rBytes = sigMem.uintBytesAt(rPtr);
        bytes memory sBytes = sigMem.uintBytesAt(sPtr);

        r = _bytesToBytes32(rBytes);
        s = _bytesToBytes32(sBytes);
    }

    /// @dev Converts variable-length bytes to bytes32 (left-padded)
    /// @param b Input bytes (length <= 32)
    /// @return result Bytes32 representation
    function _bytesToBytes32(bytes memory b) internal pure returns (bytes32 result) {
        uint256 len = b.length;
        if (len > 32) revert InputTooLong(len);

        assembly ("memory-safe") {
            // Load 32 bytes starting from the data offset
            result := mload(add(b, 0x20))

            // If length < 32, shift right to clear garbage bytes
            if lt(len, 32) {
                result := shr(mul(sub(32, len), 8), result)
            }
        }
    }
}
