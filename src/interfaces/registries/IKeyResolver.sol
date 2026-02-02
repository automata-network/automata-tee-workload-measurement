// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "../../types/Common.sol";

interface IKeyResolver {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a new public identity is registered
    /// @param fingerprint The computed fingerprint of the registered identity
    /// @param typeId Algorithm identifier for the public key type
    event IdentityRegistered(bytes32 indexed fingerprint, uint8 typeId);

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a public identity and return its fingerprint
    /// @param identity The public identity to register
    /// @return fingerprint The computed fingerprint of the identity
    function registerIdentity(PublicIdentity calldata identity) external returns (bytes32 fingerprint);

    /// @notice Get a registered identity by its fingerprint
    /// @param fingerprint The fingerprint to query
    /// @return identity The registered public identity
    function getIdentity(bytes32 fingerprint) external view returns (PublicIdentity memory identity);

    /// @notice Check if an identity is registered
    /// @param fingerprint The fingerprint to check
    /// @return True if the identity is registered
    function hasIdentity(bytes32 fingerprint) external view returns (bool);

    /// @notice Compute the fingerprint for a public identity without registering it
    /// @param identity The public identity
    /// @return fingerprint The computed fingerprint
    function computeFingerprint(PublicIdentity calldata identity) external pure returns (bytes32 fingerprint);
}
