// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

/// @title CVM Signature Base Contract
/// @notice This contract provides a template,
/// generating messages to be signed by a CVM Identity Key.
abstract contract CVMSignature {
    function _generateMessage(bytes memory userData) internal view virtual returns (bytes memory) {
        return _generateMessageWithCustomPrefix("CVM_WORKLOAD_USER_MESSAGE", userData);
    }

    function _generateMessageWithCustomPrefix(string memory prefix, bytes memory userData)
        internal
        view
        virtual
        returns (bytes memory)
    {
        return abi.encodePacked(bytes(prefix), block.chainid, address(this), userData);
    }
}
