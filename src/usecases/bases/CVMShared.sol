// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.20;

import {CertPubkey, SignatureAlgorithm, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {TPMConstants} from "@automata-network/automata-tpm-attestation/types/TPMConstants.sol";

library CVMShared {
    error TpmtPublicTooShort();
    error ParseOffsetOutOfBounds();
    error InvalidTpmtPublicType();

    function extractPubkeyFromTpmtPublic(bytes memory tpmtPublic) internal pure returns (CertPubkey memory pubkey) {
        require(tpmtPublic.length >= 10, TpmtPublicTooShort());

        uint16 keyType = uint16(bytes2(_slice(tpmtPublic, 0, 2)));

        // Skip: type(2) + nameAlg(2) + objectAttributes(4) = 8 bytes
        uint256 offset = 8;

        // Skip authPolicy (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 apLen = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2 + apLen;

        if (keyType == TPMConstants.TPM_ALG_ECC) {
            pubkey = _parseEccPublic(tpmtPublic, offset);
        } else if (keyType == TPMConstants.TPM_ALG_RSA) {
            pubkey = _parseRsaPublic(tpmtPublic, offset);
        } else {
            revert InvalidTpmtPublicType();
        }
    }

    function computeKeyHash(CertPubkey memory pubkey, SignatureAlgorithm memory sigAlgo)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(sigAlgo.scheme, pubkey.params, sigAlgo.hashAlgo, pubkey.data));
    }

    function _parseEccPublic(bytes memory tpmtPublic, uint256 offset) private pure returns (CertPubkey memory pubkey) {
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());

        // Skip symmetric
        uint16 symmetricAlgo = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            offset += 4; // skip keyBits + mode
        }

        // Skip scheme
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 scheme = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        if (scheme != TPMConstants.TPM_ALG_NULL) {
            offset += 2; // skip hashAlg
        }

        // Extract curveID
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 curveID = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;

        // Skip kdf
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 kdfScheme = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        if (kdfScheme != TPMConstants.TPM_ALG_NULL) {
            offset += 2; // skip kdf.hashAlg
        }

        // Extract x coordinate (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 xLen = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        require(offset + xLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory xBytes = _slice(tpmtPublic, offset, xLen);
        offset += xLen;

        // Extract y coordinate (TPM2B)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 yLen = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        require(offset + yLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory yBytes = _slice(tpmtPublic, offset, yLen);

        // Build uncompressed EC point (0x04 || x || y)
        require(xLen == 32 && yLen == 32, InvalidTpmtPublicType());
        bytes memory ecPoint = abi.encodePacked(uint8(0x04), xBytes, yBytes);

        pubkey = CertPubkey({algo: TPMConstants.TPM_ALG_ECC, params: curveID, data: ecPoint});
    }

    function _parseRsaPublic(bytes memory tpmtPublic, uint256 offset) private pure returns (CertPubkey memory pubkey) {
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());

        // Skip symmetric
        uint16 symmetricAlgo = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        if (symmetricAlgo != TPMConstants.TPM_ALG_NULL) {
            offset += 4; // skip keyBits + mode
        }

        // Skip scheme
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 scheme = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        if (scheme != TPMConstants.TPM_ALG_NULL) {
            offset += 2; // skip hashAlg
        }

        // Skip keyBits
        offset += 2;

        // Parse exponent (uint32, 0 means 65537)
        require(offset + 4 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint32 exponentValue = uint32(bytes4(_slice(tpmtPublic, offset, 4)));
        offset += 4;
        if (exponentValue == 0) {
            exponentValue = 65537;
        }

        // Convert exponent to bytes
        bytes memory e;
        if (exponentValue == 65537) {
            e = hex"010001";
        } else {
            e = _uint32ToBytes(exponentValue);
        }

        // Extract modulus (TPM2B_PUBLIC_KEY_RSA)
        require(offset + 2 <= tpmtPublic.length, ParseOffsetOutOfBounds());
        uint16 nLen = uint16(bytes2(_slice(tpmtPublic, offset, 2)));
        offset += 2;
        require(offset + nLen <= tpmtPublic.length, ParseOffsetOutOfBounds());
        bytes memory n = _slice(tpmtPublic, offset, nLen);

        pubkey = LibX509.newRsaPubkey(n, e);
    }

    function _uint32ToBytes(uint32 value) private pure returns (bytes memory result) {
        if (value == 0) return hex"00";

        uint256 temp = value;
        uint256 length = 0;
        while (temp > 0) {
            length++;
            temp >>= 8;
        }

        result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[length - 1 - i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function _slice(bytes memory data, uint256 start, uint256 length) private pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }
}
