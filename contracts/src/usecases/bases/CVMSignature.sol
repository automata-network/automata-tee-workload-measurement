// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {LibX509Verify} from "@automata-network/automata-tpm-attestation/lib/LibX509Verify.sol";
import {CVMIdentity} from "../../interfaces/ICVMRegistry.sol";

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

    function _verifySignature(
        CVMIdentity memory cvmIdentity,
        bytes memory signature,
        bytes memory message,
        address verifier
    ) internal view virtual returns (bool) {
        return LibX509Verify.verifySignature(cvmIdentity.pubkey, cvmIdentity.sigAlgo, message, signature, verifier);
    }
}
