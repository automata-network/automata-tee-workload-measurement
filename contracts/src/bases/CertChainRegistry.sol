// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ICertChainRegistry} from "../interfaces/ICertChainRegistry.sol";
import {CertPubkey, LibX509, ALGO_RSA, ALGO_EC} from "../lib/LibX509.sol";
import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

abstract contract CertChainRegistry is ICertChainRegistry, Ownable {
    enum CertType {
        None, // 0
        CA, // 1
        Intermediate // 2

    }

    address public immutable p256;

    // keccak256(cert) => type: 0) none, 1) CA; 2) leaf
    mapping(bytes32 => CertType) public verifiedCertIssuers;

    constructor(address _intialOwner, address _p256) Ownable(_intialOwner) {
        p256 = _p256;
    }

    function addCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        (, uint256 validityNotAfter) = LibX509.getCertValidity(ca);
        if (block.timestamp > validityNotAfter) {
            revert("cert expired");
        }
        CertPubkey memory issuer = LibX509.getCertIssuer(ca);
        bool result = verifySignature(sha256(LibX509.getCertTbs(ca)), LibX509.getCertSignature(ca), issuer);
        require(result, "verify sig failed");
        verifiedCertIssuers[key] = CertType.CA;
        emit AddCA(ca);
    }

    function removeCA(bytes calldata ca) public override onlyOwner {
        bytes32 key = keccak256(ca);
        require(verifiedCertIssuers[key] == CertType.CA, "CA not found");
        delete verifiedCertIssuers[key];
        emit RemoveCA(ca);
    }

    // certs order: leaf, intermediate, root
    function verifyCertChain(bytes[] calldata certs) public override returns (CertPubkey memory) {
        require(certs.length > 0, "CertChainRegistry: empty certs");
        CertPubkey[] memory issuers = new CertPubkey[](certs.length);
        bytes32[] memory certHashes = LibX509._getCertHashes(certs);
        require(certs.length < 5, "CertChainRegistry: too many certs");
        uint256 verified = type(uint256).max;
        uint256 certLen = certs.length;
        uint256 validityNotBefore;
        uint256 validityNotAfter;

        // check verified
        for (uint256 i = 0; i < certLen; i++) {
            issuers[i] = LibX509.getCertIssuer(certs[i]);
            CertType cachedCertType = verifiedCertIssuers[certHashes[i]];
            if (i == certLen - 1 && cachedCertType == CertType.CA) {
                verified = i;
                break;
            } else if (i < certLen - 1 && cachedCertType == CertType.Intermediate) {
                verified = i;
                break;
            }
        }

        if (verified == type(uint256).max) {
            revert("CertChainRegistry: no CA found");
        }

        // check validity of leaf cert
        (validityNotBefore, validityNotAfter) = LibX509.getCertValidity(certs[0]);
        if (validityNotBefore > block.timestamp || validityNotAfter < block.timestamp) {
            revert("cert not valid yet");
        }

        for (uint256 i = 0; i < verified; i++) {
            bytes memory sig = LibX509.getCertSignature(certs[i]);
            if (issuers[i + 1].algo == ALGO_RSA) {
                bool result = verifySignature(sha256(LibX509.getCertTbs(certs[i])), sig, issuers[i + 1]);
                require(result, "verify sig failed");
            } else {
                revert("CertChainRegistry: unsupported EC");
            }
        }

        // cache result
        for (uint256 i = 0; i < verified; i++) {
            verifiedCertIssuers[certHashes[i]] = CertType.Intermediate;
        }
        return issuers[0];
    }

    function verifySignature(bytes32 digest, bytes memory sig, CertPubkey memory pubkey)
        public
        view
        override
        returns (bool)
    {
        if (pubkey.algo == ALGO_RSA) {
            (bytes memory n, bytes memory e) = LibX509.rsaPub(pubkey.data);
            bool result = RSA.pkcs1Sha256(digest, sig, e, n);
            return result;
        } else if (pubkey.algo == ALGO_EC) {
            require(sig.length == 64, "invalid r size");
            bytes32 r;
            bytes32 s;
            assembly {
                let offset := add(sig, 0x20) // length
                r := mload(offset)
                offset := add(offset, 0x20)
                s := mload(offset)
            }
            (bytes32 x, bytes32 y) = pubkey.ec();
            return _ecdsaVerify(digest, r, s, x, y);
        } else {
            revert("CertChainRegistry: unsupported pubkey algo");
        }
    }

    function _ecdsaVerify(bytes32 messageHash, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        private
        view
        returns (bool verified)
    {
        bytes memory args = abi.encode(messageHash, r, s, x, y);
        (bool success, bytes memory ret) = p256.staticcall(args);
        assert(success); // never reverts, always returns 0 or 1
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
