// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IMaaKeyRegistry, MaaSigningKey} from "./interfaces/registries/IMaaKeyRegistry.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title MaaKeyRegistry
/// @notice Admin-managed directory of Microsoft Azure Attestation signing keys for AzureMaaJwt
///         AK collateral verification (§8.3.1, §10.3).
/// @dev Admin operations gated by `OwnableUpgradeable.onlyOwner`. The EVM tx nonce provides
///      replay protection; no separate signed-message envelope is needed. The owner key is
///      the root of trust for the entire Azure attestation path on this deployment, so
///      treat it accordingly (multisig / time-locked rotation / etc.).
contract MaaKeyRegistry is IMaaKeyRegistry, OwnableUpgradeable, UUPSUpgradeable {
    // ============================================================================
    // Errors
    // ============================================================================

    /// @notice Pkcs1Pubkey is empty
    error EmptyPubkey();

    /// @notice IssuerHash is the zero hash
    error EmptyIssuerHash();

    /// @notice notAfter is in the past at submission time
    error NotAfterInPast(uint64 notAfter, uint64 nowTs);

    /// @notice Attempted to revoke a kid that was never registered
    error KidNotRegistered(bytes32 kidHash);

    /// @notice Attempted to upsert a kid that was permanently revoked
    error KidRevoked(bytes32 kidHash);

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
    constructor() {
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
    function upsertMaaSigningKey(bytes32 kidHash, bytes calldata pkcs1Pubkey, bytes32 issuerHash, uint64 notAfter)
        external
        onlyOwner
    {
        if (_keys[kidHash].revoked) revert KidRevoked(kidHash);
        if (pkcs1Pubkey.length == 0) revert EmptyPubkey();
        if (issuerHash == bytes32(0)) revert EmptyIssuerHash();
        if (notAfter < block.timestamp) revert NotAfterInPast(notAfter, uint64(block.timestamp));

        _keys[kidHash] =
            MaaSigningKey({pkcs1Pubkey: pkcs1Pubkey, issuerHash: issuerHash, notAfter: notAfter, revoked: false});

        emit MaaSigningKeyUpserted(kidHash, issuerHash, notAfter);
    }

    /// @inheritdoc IMaaKeyRegistry
    function revokeMaaSigningKey(bytes32 kidHash) external onlyOwner {
        if (_keys[kidHash].pkcs1Pubkey.length == 0) revert KidNotRegistered(kidHash);
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
