// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {CertPubkey} from "../lib/LibX509.sol";

/**
 * @title Certificate Chain Registry Interface
 * @notice This is a simple interface for managing certificate authorities (CAs) and verifying certificate chains.
 */
interface ICertChainRegistry {
    event AddCA(bytes ca);
    event RemoveCA(bytes ca);

    /**
     * @notice Adds a Certificate Authority (CA) to the registry.
     * @param ca - The X509 Certificate Authority (CA) in DER format.
     * @dev should implement access-control
     */
    function addCA(bytes calldata ca) external;

    /**
     * @notice Removes a Certificate Authority (CA) from the registry.
     * @param ca - The X509 Certificate Authority (CA) in DER format.
     * @dev should implement access-control
     */
    function removeCA(bytes calldata ca) external;

    /**
     * @notice Verifies a certificate chain
     * @param certs - An array of X509 certificates in DER format.
     * @return the public key of the leaf certificate
     */
    function verifyCertChain(bytes[] calldata certs) external returns (CertPubkey memory);

    /**
     * @notice Verifies a digital signature
     * @param digest - The hash of the data that was signed
     * @param sig - The digital signature
     * @param pubkey - The public key of the signer
     */
    function verifySignature(bytes32 digest, bytes memory sig, CertPubkey memory pubkey) external view returns (bool);
}
