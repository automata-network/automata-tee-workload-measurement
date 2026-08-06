// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    PcrBankSelection,
    PcrCommitment,
    PcrPolicyBlock,
    PcrPolicyBlockMetadata,
    PcrSpec256,
    PcrSpec384
} from "../types/Common.sol";
import {
    AWS_REPORT_DATA_PCR_COMMITMENT_DOMAIN,
    PCR_POLICY_BLOCK_DOMAIN,
    TPM_POLICY_COMMITMENT_DOMAIN
} from "../types/Constants.sol";

library PcrPolicy {
    uint16 internal constant TPM_ALG_SHA256 = 0x000B;
    uint16 internal constant TPM_ALG_SHA384 = 0x000C;

    function hashBlock(PcrPolicyBlock memory policyBlock) internal pure returns (bytes32) {
        return keccak256(abi.encode(PCR_POLICY_BLOCK_DOMAIN, policyBlock.pcrSpecs256, policyBlock.pcrSpecs384));
    }

    function metadataCalldata(PcrPolicyBlock calldata policyBlock)
        internal
        pure
        returns (PcrPolicyBlockMetadata memory result)
    {
        result.blockHash =
            keccak256(abi.encode(PCR_POLICY_BLOCK_DOMAIN, policyBlock.pcrSpecs256, policyBlock.pcrSpecs384));
        result.pcrSelectBitmap256 = bitmap256Calldata(policyBlock.pcrSpecs256);
        result.pcrSelectBitmap384 = bitmap384Calldata(policyBlock.pcrSpecs384);
    }

    function metadataMemory(PcrPolicyBlock memory policyBlock)
        internal
        pure
        returns (PcrPolicyBlockMetadata memory result)
    {
        result.blockHash = hashBlock(policyBlock);
        result.pcrSelectBitmap256 = bitmap256Memory(policyBlock.pcrSpecs256);
        result.pcrSelectBitmap384 = bitmap384Memory(policyBlock.pcrSpecs384);
    }

    function policyCommitment(
        bytes32 invariantBlockHash,
        bytes32 variantBlockHash,
        bytes32 workloadBlockHash,
        bytes32 providerBlockHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TPM_POLICY_COMMITMENT_DOMAIN, invariantBlockHash, variantBlockHash, workloadBlockHash, providerBlockHash
            )
        );
    }

    function awsReportDataPcrCommitmentHash(PcrCommitment memory commitment) internal pure returns (bytes32) {
        return keccak256(abi.encode(AWS_REPORT_DATA_PCR_COMMITMENT_DOMAIN, commitment.pcrSelect, commitment.pcrDigest));
    }

    function combinePcrSelect(
        PcrBankSelection bankSelection,
        PcrPolicyBlockMetadata memory invariantMetadata,
        PcrPolicyBlockMetadata memory variantMetadata,
        PcrPolicyBlockMetadata memory workloadMetadata,
        PcrPolicyBlockMetadata memory providerMetadata
    ) internal pure returns (bytes32) {
        bytes3 bitmap256 = invariantMetadata.pcrSelectBitmap256 | variantMetadata.pcrSelectBitmap256
            | workloadMetadata.pcrSelectBitmap256 | providerMetadata.pcrSelectBitmap256;
        bytes3 bitmap384 = invariantMetadata.pcrSelectBitmap384 | variantMetadata.pcrSelectBitmap384
            | workloadMetadata.pcrSelectBitmap384 | providerMetadata.pcrSelectBitmap384;

        if (bankSelection == PcrBankSelection.Sha256) return packPcrSelect(bitmap256, bytes3(0));
        if (bankSelection == PcrBankSelection.Sha384) return packPcrSelect(bytes3(0), bitmap384);
        return packPcrSelect(bitmap256, bitmap384);
    }

    function packPcrSelect(bytes3 bitmap256, bytes3 bitmap384) internal pure returns (bytes32 packed) {
        uint256 value;
        if (bitmap256 != bytes3(0)) {
            value = (uint256(TPM_ALG_SHA256) << 240) | (uint256(uint24(bitmap256)) << 216);
            if (bitmap384 != bytes3(0)) {
                value |= (uint256(TPM_ALG_SHA384) << 200) | (uint256(uint24(bitmap384)) << 176);
            }
        } else if (bitmap384 != bytes3(0)) {
            value = (uint256(TPM_ALG_SHA384) << 240) | (uint256(uint24(bitmap384)) << 216);
        }
        packed = bytes32(value);
    }

    function bitmap256Calldata(PcrSpec256[] calldata specs) internal pure returns (bytes3 bitmap) {
        for (uint256 i; i < specs.length; ++i) {
            bitmap = _setBit(bitmap, specs[i].pcrIndex);
        }
    }

    function bitmap384Calldata(PcrSpec384[] calldata specs) internal pure returns (bytes3 bitmap) {
        for (uint256 i; i < specs.length; ++i) {
            bitmap = _setBit(bitmap, specs[i].pcrIndex);
        }
    }

    function bitmap256Memory(PcrSpec256[] memory specs) internal pure returns (bytes3 bitmap) {
        for (uint256 i; i < specs.length; ++i) {
            bitmap = _setBit(bitmap, specs[i].pcrIndex);
        }
    }

    function bitmap384Memory(PcrSpec384[] memory specs) internal pure returns (bytes3 bitmap) {
        for (uint256 i; i < specs.length; ++i) {
            bitmap = _setBit(bitmap, specs[i].pcrIndex);
        }
    }

    function _setBit(bytes3 bitmap, uint8 pcrIndex) private pure returns (bytes3) {
        uint256 byteIndex = uint256(pcrIndex) >> 3;
        uint256 bitIndex = uint256(pcrIndex) & 7;
        uint256 shift = (2 - byteIndex) * 8 + bitIndex;
        return bytes3(uint24(bitmap) | uint24(uint256(1) << shift));
    }
}
