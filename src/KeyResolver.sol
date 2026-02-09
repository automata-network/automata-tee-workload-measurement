// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "./types/Common.sol";
import {ALGO_ID_NULL} from "./types/Constants.sol";
import {IKeyResolver} from "./interfaces/registries/IKeyResolver.sol";
import {LibKey} from "./lib/LibKey.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title KeyResolver
/// @notice Registry for CVM session key identities with fingerprint-based lookups
/// @dev Stores PublicIdentity structs indexed by their domain-separated fingerprint
///      Fingerprints are computed as: keccak256(abi.encode(KEY_DOMAIN, typeId, key))
contract KeyResolver is IKeyResolver, OwnableUpgradeable, UUPSUpgradeable {
    // ============================================================================
    // Errors
    // ============================================================================

    /// @notice Identity not found for the given fingerprint
    error IdentityNotFound(bytes32 fingerprint);

    /// @notice Invalid identity (empty key or invalid typeId)
    error InvalidIdentity();

    // ============================================================================
    // Storage
    // ============================================================================

    /// @dev Maps fingerprint → PublicIdentity
    /// @dev Existence check: _identities[fp].typeId != ALG_ID_NULL (typeId is 1-indexed)
    mapping(bytes32 => PublicIdentity) private _identities;
    /// @dev Storage gap for future upgrades (1 existing mapping → 49-slot gap)
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

    /// @inheritdoc IKeyResolver
    function computeFingerprint(PublicIdentity calldata identity) external pure returns (bytes32 fingerprint) {
        return LibKey.computeKeyFingerprint(identity);
    }

    /// @inheritdoc IKeyResolver
    function registerIdentity(PublicIdentity calldata identity) external returns (bytes32 fingerprint) {
        // Validate identity
        if (identity.typeId == ALGO_ID_NULL || identity.key.length == 0) {
            revert InvalidIdentity();
        }

        // Compute fingerprint
        fingerprint = LibKey.computeKeyFingerprint(identity);

        // Check if already registered (idempotent)
        if (_identities[fingerprint].typeId != ALGO_ID_NULL) {
            return fingerprint;
        }

        // Store identity
        _identities[fingerprint] = identity;

        emit IdentityRegistered(fingerprint, identity.typeId);
    }

    /// @inheritdoc IKeyResolver
    function getIdentity(bytes32 fingerprint) external view returns (PublicIdentity memory identity) {
        identity = _identities[fingerprint];
        if (identity.typeId == ALGO_ID_NULL) {
            revert IdentityNotFound(fingerprint);
        }
    }

    /// @inheritdoc IKeyResolver
    function hasIdentity(bytes32 fingerprint) external view returns (bool) {
        return _identities[fingerprint].typeId != ALGO_ID_NULL;
    }

    // ============================================================================
    // Internal Functions - UUPS
    // ============================================================================

    /// @dev Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
