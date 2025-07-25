// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {Asn1Decode, NodePtr} from "./Asn1Decode.sol";
import {LibBytes} from "./LibBytes.sol";
import {DateTimeLib} from "@solady/utils/DateTimeLib.sol";

uint8 constant ALGO_EC = 1;
uint8 constant ALGO_RSA = 2;

struct CertPubkey {
    uint8 algo;
    bytes data;
}

using LibX509 for CertPubkey global;

library LibX509 {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using LibBytes for bytes;

    function newRsaPubkey(bytes memory e, bytes memory n) internal pure returns (CertPubkey memory) {
        // RSAPublicKey ::= SEQ { n, e }
        uint256 nLength = n[0] < 0x80 ? n.length : n.length + 1;
        uint256 eLength = e[0] < 0x80 ? e.length : e.length + 1;
        require(nLength > 0x80 && nLength < 65565 && eLength < 0x80, "invalid e or n");

        bytes memory der = abi.encodePacked(uint8(0x30), uint8(0x82), uint16(4 + nLength + 2 + eLength));
        if (n[0] >= 0x80) {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), uint8(0x0), n);
        } else {
            der = abi.encodePacked(der, uint16(0x0282), uint16(nLength), n);
        }
        if (e[0] >= 0x80) {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), uint8(0x0), e);
        } else {
            der = abi.encodePacked(der, uint8(0x02), uint8(eLength), e);
        }

        return CertPubkey({algo: ALGO_RSA, data: der});
    }

    function empty(CertPubkey memory pubkey) internal pure returns (bool) {
        return pubkey.data.length == 0;
    }

    function ec(CertPubkey memory pubkey) internal pure returns (bytes32, bytes32) {
        bytes memory data = pubkey.data;
        bytes32 x;
        bytes32 y;
        assembly {
            x := mload(add(data, 0x21))
            y := mload(add(data, 0x41))
        }
        return (x, y);
    }

    function _getSubjectPublicKey(bytes memory der, uint256 subjectPublicKeyInfoPtr)
        private
        pure
        returns (CertPubkey memory pubkey)
    {
        bytes memory key = der.bytesAt(subjectPublicKeyInfoPtr);
        (bytes memory oid,) = _getOid(key);
        if (oid.equal(hex"2a864886f70d010101")) {
            pubkey.algo = ALGO_RSA;
        } else if (oid.equal(hex"2a8648ce3d0201")) {
            pubkey.algo = ALGO_EC;
        } else {
            revert("unknown pubkey algo");
        }

        subjectPublicKeyInfoPtr = der.nextSiblingOf(subjectPublicKeyInfoPtr);
        pubkey.data = der.bitstringAt(subjectPublicKeyInfoPtr);
        if (pubkey.algo == ALGO_EC) {
            if (pubkey.data.length != 65 || pubkey.data[0] != 0x04) {
                revert("compressed public key not supported");
            }
        }
    }

    function _getValidity(bytes memory der, uint256 validityPtr)
        internal
        pure
        returns (uint256 notBefore, uint256 notAfter)
    {
        uint256 notBeforePtr = der.firstChildOf(validityPtr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        notBefore = fromDERToTimestamp(der.bytesAt(notBeforePtr));
        notAfter = fromDERToTimestamp(der.bytesAt(notAfterPtr));
    }

    function _decodeSequence(bytes memory value) private pure returns (bytes memory) {
        require(value[0] == 0x30, "Not a sequence");
        if (value[1] == 0x80) {
            require(false, "Not supported");
        }
        return value.slice(2, uint256(uint8(value[1])));
    }

    function _getCertHashes(bytes[] memory certs) internal pure returns (bytes32[] memory certHashes) {
        uint256 certLen = certs.length;
        certHashes = new bytes32[](certLen);
        unchecked {
            for (uint256 i = certLen - 1; i >= 0; i--) {
                if (i == certLen - 1) {
                    certHashes[i] = keccak256(certs[i]);
                } else {
                    certHashes[i] = keccak256(abi.encodePacked(certHashes[i + 1], sha256(certs[i])));
                }

                if (i == 0) {
                    break; // Prevent underflow
                }
            }
        }
    }

    function _getOid(bytes memory value) private pure returns (bytes memory, uint256) {
        require(value[0] == 0x06, "Not a OID");
        uint256 oidLen = uint256(uint8(value[1]));
        return (value.slice(2, oidLen), oidLen + 2);
    }

    function getCertTbs(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        return der.allBytesAt(tbsParentPtr);
    }

    function getCertSignature(bytes memory der) internal pure returns (bytes memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root); // tbs
        uint256 sigPtr = der.nextSiblingOf(tbsParentPtr); // sig algo
        sigPtr = der.nextSiblingOf(sigPtr); // sig
        return der.bitstringAt(sigPtr);
    }

    function getCertValidity(bytes memory der)
        internal
        pure
        returns (uint256 validityNotBefore, uint256 validityNotAfter)
    {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        (validityNotBefore, validityNotAfter) = _getValidity(der, tbsPtr);
    }

    function getCertIssuer(bytes calldata der) internal pure returns (CertPubkey memory) {
        uint256 root = der.root();
        uint256 tbsParentPtr = der.firstChildOf(root);
        uint256 tbsPtr = der.firstChildOf(tbsParentPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        tbsPtr = der.nextSiblingOf(tbsPtr);
        CertPubkey memory subjectPublicKey = _getSubjectPublicKey(der, der.firstChildOf(tbsPtr));
        return subjectPublicKey;
    }

    function rsaPub(bytes memory der) internal pure returns (bytes memory n, bytes memory e) {
        uint256 root = der.root();
        uint256 parentPtr = der.firstChildOf(root);
        uint256 next = der.nextSiblingOf(parentPtr);
        n = der.bytesAt(parentPtr);

        // trim prefix 0
        for (uint256 i = 0; i < n.length; i++) {
            if (n[i] != 0x00) {
                if (i > 0) {
                    n = n.slice(i, n.length - i);
                }
                break;
            }
        }
        e = der.bytesAt(next);
    }

    function fromDERToTimestamp(bytes memory x509Time) internal pure returns (uint256) {
        uint16 yrs;
        uint8 mnths;
        uint8 dys;
        uint8 hrs;
        uint8 mins;
        uint8 secs;
        uint8 offset;

        if (x509Time.length == 13) {
            if (uint8(x509Time[0]) - 48 < 5) yrs += 2000;
            else yrs += 1900;
        } else {
            yrs += (uint8(x509Time[0]) - 48) * 1000 + (uint8(x509Time[1]) - 48) * 100;
            offset = 2;
        }
        yrs += (uint8(x509Time[offset + 0]) - 48) * 10 + uint8(x509Time[offset + 1]) - 48;
        mnths = (uint8(x509Time[offset + 2]) - 48) * 10 + uint8(x509Time[offset + 3]) - 48;
        dys += (uint8(x509Time[offset + 4]) - 48) * 10 + uint8(x509Time[offset + 5]) - 48;
        hrs += (uint8(x509Time[offset + 6]) - 48) * 10 + uint8(x509Time[offset + 7]) - 48;
        mins += (uint8(x509Time[offset + 8]) - 48) * 10 + uint8(x509Time[offset + 9]) - 48;
        secs += (uint8(x509Time[offset + 10]) - 48) * 10 + uint8(x509Time[offset + 11]) - 48;

        return DateTimeLib.dateTimeToTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }
}
