// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ISignatureVerifier} from "../interfaces/ISignatureVerifier.sol";
import {PublicIdentity} from "../types/Common.sol";

/// @title MockSignatureVerifier
/// @notice Mock signature verifier for development/testing that accepts all signatures
/// @dev Always returns true for any signature verification request, enabling the full
///      SessionRegistry flow to work without real cryptographic signatures.
contract MockSignatureVerifier is ISignatureVerifier {
    /// @inheritdoc ISignatureVerifier
    function verify(PublicIdentity calldata, bytes32, bytes calldata) external pure returns (bool valid) {
        return true;
    }
}
