// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {CertPubkey} from "../lib/LibX509.sol";

interface ICertChainRegistry {
    event AddCA(bytes ca);
    event RemoveCA(bytes ca);

    function addCA(bytes calldata ca) external;
    function verifyCertChain(bytes[] calldata certs) external returns (CertPubkey memory);
    function verifySignature(bytes32 digest, bytes memory sig, CertPubkey memory pubkey) external view returns (bool);

    function owner() external view returns (address);
    function version() external view returns (string memory);
    function __constructor__() external;
    function initialize(address _initialOwner) external;
}
