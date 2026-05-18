// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "../../types/Common.sol";

/// @notice Pre-registered Microsoft Azure Attestation signing key
/// @dev Empty (revoked == false && pkcs1Pubkey.length == 0) indicates the kid is not registered.
struct MaaSigningKey {
    /// @dev DER PKCS#1 RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e }); ~270 bytes for RSA-2048.
    ///      Same shape consumed by SignatureVerifier._verifyRsa.
    bytes pkcs1Pubkey;
    /// @dev keccak256(bytes("https://<region>.attest.azure.net")) — the JWT iss claim hash
    bytes32 issuerHash;
    /// @dev Unix seconds; from the leaf certificate NotAfter
    uint64 notAfter;
    /// @dev Admin-set revocation flag; overrides notAfter
    bool revoked;
}

/// @notice MaaKeyRegistry — admin-managed directory of Microsoft Azure Attestation signing keys
/// @dev Distinct from KeyResolver because the stored value shape (PKCS#1 RSA pubkey + issuer +
///      validity + revocation) and lifecycle (rotation, expiry, admin revocation) differ from a
///      PublicIdentity directory. Held by SessionRegistry as an immutable reference, consumed
///      by AkCollateralVerifier when verifying AzureMaaJwt collateral (§8.3.1, §10.3).
interface IMaaKeyRegistry {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a MAA signing key is inserted or replaced
    /// @param kidHash keccak256(bytes(jwt.header.kid))
    /// @param issuerHash keccak256(bytes(jwt.claims.iss))
    /// @param notAfter Unix seconds; key is invalid after this time
    event MaaSigningKeyUpserted(bytes32 indexed kidHash, bytes32 issuerHash, uint64 notAfter);

    /// @notice Emitted when a MAA signing key is revoked
    /// @param kidHash keccak256(bytes(jwt.header.kid))
    event MaaSigningKeyRevoked(bytes32 indexed kidHash);

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Insert or replace a MAA signing key
    /// @dev Owner-signed message:
    ///      sha256(abi.encode(MAA_KEY_UPSERT_MSG, block.chainid, address(this), expireAt,
    ///                        kidHash, pkcs1Pubkey, issuerHash, notAfter))
    /// @param kidHash keccak256(bytes(jwt.header.kid))
    /// @param pkcs1Pubkey DER PKCS#1 RSAPublicKey
    /// @param issuerHash keccak256(bytes(MAA endpoint URL))
    /// @param notAfter Unix seconds; key validity window end
    /// @param expireAt Signature expiry (replay protection)
    /// @param ownerIdentity Registry owner public identity
    /// @param ownerSignature Owner's signature over the operation message
    function upsertMaaSigningKey(
        bytes32 kidHash,
        bytes calldata pkcs1Pubkey,
        bytes32 issuerHash,
        uint64 notAfter,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Revoke a MAA signing key. Subsequent JWT verifications against this kid revert
    ///         regardless of notAfter.
    /// @dev Owner-signed message:
    ///      sha256(abi.encode(MAA_KEY_REVOKE_MSG, block.chainid, address(this), expireAt, kidHash))
    function revokeMaaSigningKey(
        bytes32 kidHash,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Returns the stored MaaSigningKey for `kidHash`. An empty result
    ///         (pkcs1Pubkey.length == 0 && !revoked) indicates the kid is not registered.
    function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory);

    /// @notice Returns true when the kid is registered and not revoked. Does not check notAfter —
    ///         time-window enforcement is the verifier's responsibility (block.timestamp may not be
    ///         meaningful for some callers).
    function hasMaaSigningKey(bytes32 kidHash) external view returns (bool);
}
