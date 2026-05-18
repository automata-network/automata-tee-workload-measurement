// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "./types/Common.sol";
import {MAA_KEY_UPSERT_MSG, MAA_KEY_REVOKE_MSG} from "./types/Constants.sol";
import {ISignatureVerifier} from "./interfaces/ISignatureVerifier.sol";
import {IMaaKeyRegistry, MaaSigningKey} from "./interfaces/registries/IMaaKeyRegistry.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title MaaKeyRegistry
/// @notice Admin-managed directory of Microsoft Azure Attestation signing keys for AzureMaaJwt
///         AK collateral verification (§8.3.1, §10.3).
/// @dev Owner-signed admin operations; per-operation message includes chainid + address(this)
///      for replay protection, matching the BaseImageRegistry / WorkloadRegistry pattern.
contract MaaKeyRegistry is IMaaKeyRegistry, OwnableUpgradeable, UUPSUpgradeable {
    // ============================================================================
    // Errors
    // ============================================================================

    /// @notice Signature has expired
    error SignatureExpired();

    /// @notice Owner signature is invalid
    error InvalidSignature();

    /// @notice Pkcs1Pubkey is empty
    error EmptyPubkey();

    /// @notice IssuerHash is the zero hash
    error EmptyIssuerHash();

    /// @notice notAfter is in the past at submission time
    error NotAfterInPast();

    // ============================================================================
    // Immutables
    // ============================================================================

    /// @notice Signature verifier used to authenticate owner-signed admin operations
    ISignatureVerifier public immutable signatureVerifier;

    // ============================================================================
    // Storage
    // ============================================================================

    /// @dev kidHash -> MaaSigningKey. Empty pkcs1Pubkey indicates an unregistered kid.
    mapping(bytes32 => MaaSigningKey) private _keys;

    /// @dev Storage gap for future upgrades (1 mapping → 49-slot gap)
    uint256[49] private __gap;

    // ============================================================================
    // Constructor & Initialization
    // ============================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(ISignatureVerifier _signatureVerifier) {
        signatureVerifier = _signatureVerifier;
        _disableInitializers();
    }

    /// @notice Initializes the contract with the initial owner
    /// @param initialOwner The address that will own the contract
    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
    }

    // ============================================================================
    // External Functions
    // ============================================================================

    /// @inheritdoc IMaaKeyRegistry
    function upsertMaaSigningKey(
        bytes32 kidHash,
        bytes calldata pkcs1Pubkey,
        bytes32 issuerHash,
        uint64 notAfter,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        if (block.timestamp > expireAt) revert SignatureExpired();
        if (pkcs1Pubkey.length == 0) revert EmptyPubkey();
        if (issuerHash == bytes32(0)) revert EmptyIssuerHash();
        if (notAfter <= block.timestamp) revert NotAfterInPast();

        bytes32 message = sha256(
            abi.encode(
                MAA_KEY_UPSERT_MSG,
                block.chainid,
                address(this),
                expireAt,
                kidHash,
                pkcs1Pubkey,
                issuerHash,
                notAfter
            )
        );

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        _keys[kidHash] = MaaSigningKey({
            pkcs1Pubkey: pkcs1Pubkey,
            issuerHash: issuerHash,
            notAfter: notAfter,
            revoked: false
        });

        emit MaaSigningKeyUpserted(kidHash, issuerHash, notAfter);
    }

    /// @inheritdoc IMaaKeyRegistry
    function revokeMaaSigningKey(
        bytes32 kidHash,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external {
        if (block.timestamp > expireAt) revert SignatureExpired();

        bytes32 message =
            sha256(abi.encode(MAA_KEY_REVOKE_MSG, block.chainid, address(this), expireAt, kidHash));

        if (!signatureVerifier.verify(ownerIdentity, message, ownerSignature)) {
            revert InvalidSignature();
        }

        _keys[kidHash].revoked = true;

        emit MaaSigningKeyRevoked(kidHash);
    }

    /// @inheritdoc IMaaKeyRegistry
    function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory) {
        return _keys[kidHash];
    }

    /// @inheritdoc IMaaKeyRegistry
    function hasMaaSigningKey(bytes32 kidHash) external view returns (bool) {
        MaaSigningKey storage k = _keys[kidHash];
        return k.pkcs1Pubkey.length != 0 && !k.revoked;
    }

    // ============================================================================
    // Internal Functions - UUPS
    // ============================================================================

    /// @dev Authorizes an upgrade to a new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
