// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {CVMIdentity} from "../../interfaces/ICVMRegistry.sol";
import {CertPubkey, SignatureAlgorithm} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {TPMConstants} from "@automata-network/automata-tpm-attestation/types/TPMConstants.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";

/// @title CVM Signature Base Contract
/// @notice This contract provides a template,
/// generating messages to be signed by a CVM Identity Key.
abstract contract CVMSignature {
    bytes32 constant P256_VERIFIER_SLOT = keccak256("automata.contracts.usecases.CVMSignature.p256Verifier");

    error UnsupportedHashAlgorithm(uint16 hashAlgorithm);
    error UnsupportedSignatureAlgorithm(uint16 signatureAlgorithm);
    error IncorrectPubkeyLength();
    error IncorrectSignatureLength();
    error InvalidSignature();

    function P256_VERIFIER() public view returns (address) {
        return StorageSlot.getAddressSlot(P256_VERIFIER_SLOT).value;
    }

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

    /// @dev use this method to update the P256 verifier contract address
    function _writeP256VerifyAddress(address p256VerifierAddress) internal {
        StorageSlot.getAddressSlot(P256_VERIFIER_SLOT).value = p256VerifierAddress;
    }

    function _verifySignature(CVMIdentity memory cvmIdentity, bytes memory signature, bytes memory message)
        internal
        view
        virtual
        returns (bool verified)
    {
        CertPubkey memory pubkey = cvmIdentity.pubkey;
        SignatureAlgorithm memory sigAlgo = cvmIdentity.sigAlgo;

        bytes32 digest;
        if (sigAlgo.hashAlgo == TPMConstants.TPM_ALG_SHA256) {
            digest = sha256(message);
        } else {
            revert UnsupportedHashAlgorithm(sigAlgo.hashAlgo);
        }

        if (sigAlgo.scheme == TPMConstants.TPM_ALG_RSASSA) {
            verified = _verifyRsaSignature(pubkey, signature, digest);
        } else if (sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA) {
            verified = _verifyEcdsaSignature(pubkey, signature, digest);
        } else {
            revert UnsupportedSignatureAlgorithm(sigAlgo.scheme);
        }
    }

    function _verifyRsaSignature(CertPubkey memory pubkey, bytes memory signature, bytes32 digest)
        private
        view
        returns (bool verified)
    {
        // Extract RSA public key parameters
        (bytes memory n, bytes memory e) = pubkey.rsa();

        // Validate signature length matches modulus size
        require(signature.length == n.length, IncorrectSignatureLength());

        // RSASSA (PKCS#1 v1.5) verification
        return RSA.pkcs1Sha256(digest, signature, e, n);
    }

    function _verifyEcdsaSignature(CertPubkey memory pubkey, bytes memory signature, bytes32 digest)
        private
        view
        returns (bool verified)
    {
        // Extract ECDSA public key parameters
        (bytes32 x, bytes32 y) = pubkey.ecP256();

        // Extract R,S from signature
        bytes32 r;
        bytes32 s;
        if (signature.length != 64) {
            revert IncorrectSignatureLength();
        }
        assembly {
            let offset := add(signature, 0x20) // length
            r := mload(offset)
            offset := add(offset, 0x20)
            s := mload(offset)
        }

        // Call the P256 verifier contract with signature and public key data
        bytes memory args = abi.encode(digest, r, s, x, y);
        (bool success, bytes memory ret) = P256_VERIFIER().staticcall(args);

        if (!success || ret.length != 32) {
            return false;
        }

        // Decode return value: 1 = valid signature, 0 = invalid signature
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
