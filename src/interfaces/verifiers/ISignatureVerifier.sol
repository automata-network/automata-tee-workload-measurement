// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "../../types/Common.sol";

/// @title ISignatureVerifier
/// @notice On-chain verification of cryptographic signatures against PublicIdentity keys
/// @dev Foundation of the owner-auth model - allows TEE-managed keys (RSA, ECDSA-P256, etc.)
///      to own registry entries directly without relying on msg.sender addresses
interface ISignatureVerifier {
    /// @notice Verifies a cryptographic signature against a public identity
    /// @param identity The public key identity to verify against
    /// @param message The message hash that was signed (hash algorithm dictated by the signature scheme)
    /// @param signature The cryptographic signature bytes (format depends on identity.typeId)
    /// @return valid True if the signature is valid for the given identity and message
    function verify(PublicIdentity calldata identity, bytes32 message, bytes calldata signature)
        external
        view
        returns (bool valid);
}
