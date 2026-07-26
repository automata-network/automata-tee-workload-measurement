// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {SNP_PLATFORM_INFO_SUPPORTED_MASK} from "../types/Constants.sol";

/// @notice Validation and comparison helpers for packed AMD SEV-SNP policy values.
library AmdSnpPolicy {
    uint256 private constant TCB_LANE_MASK = type(uint64).max;
    uint64 private constant TCB_SUPPORTED_COMPONENT_MASK = type(uint32).max;

    error InvalidAmdSnpTcbValue(bytes32 actual);
    error InvalidAmdSnpPlatformInfoPolicy(bytes32 actual);

    /// @notice Validates the four packed AMD SEV-SNP TCB lanes.
    /// @dev Each 64-bit lane currently permits bootloader, TEE, SNP, and microcode.
    ///      The FMC byte and all upper reserved bits must remain zero until Turin is supported.
    function validateTcb(bytes32 packedTcb) internal pure {
        uint256 packed = uint256(packedTcb);
        for (uint256 shift = 0; shift < 256; shift += 64) {
            uint64 lane = uint64((packed >> shift) & TCB_LANE_MASK);
            if ((lane & ~TCB_SUPPORTED_COMPONENT_MASK) != 0) {
                revert InvalidAmdSnpTcbValue(packedTcb);
            }
        }
    }

    /// @notice Validates the packed required-set and required-clear PLATFORM_INFO masks.
    function validatePlatformInfoPolicy(bytes32 packedPolicy) internal pure {
        uint256 packed = uint256(packedPolicy);
        uint64 requiredSet = uint64(packed);
        uint64 requiredClear = uint64(packed >> 64);
        if (
            (packed >> 128) != 0 || (requiredSet & ~SNP_PLATFORM_INFO_SUPPORTED_MASK) != 0
                || (requiredClear & ~SNP_PLATFORM_INFO_SUPPORTED_MASK) != 0 || (requiredSet & requiredClear) != 0
        ) {
            revert InvalidAmdSnpPlatformInfoPolicy(packedPolicy);
        }
    }

    /// @notice Returns the component-wise maximum of two packed four-lane TCB values.
    function maxTcb(bytes32 left, bytes32 right) internal pure returns (bytes32 result) {
        uint256 leftValue = uint256(left);
        uint256 rightValue = uint256(right);
        uint256 packed;
        for (uint256 laneShift = 0; laneShift < 256; laneShift += 64) {
            uint64 leftLane = uint64(leftValue >> laneShift);
            uint64 rightLane = uint64(rightValue >> laneShift);
            uint64 maximum;
            for (uint256 componentShift = 0; componentShift < 32; componentShift += 8) {
                uint8 leftComponent = uint8(leftLane >> componentShift);
                uint8 rightComponent = uint8(rightLane >> componentShift);
                maximum |= uint64(leftComponent > rightComponent ? leftComponent : rightComponent)
                << uint64(componentShift);
            }
            packed |= uint256(maximum) << laneShift;
        }
        return bytes32(packed);
    }

    /// @notice Returns true when every actual TCB component meets its minimum.
    function tcbMeetsMinimum(bytes32 actual, bytes32 minimum) internal pure returns (bool) {
        uint256 actualValue = uint256(actual);
        uint256 minimumValue = uint256(minimum);
        for (uint256 laneShift = 0; laneShift < 256; laneShift += 64) {
            uint64 actualLane = uint64(actualValue >> laneShift);
            uint64 minimumLane = uint64(minimumValue >> laneShift);
            for (uint256 componentShift = 0; componentShift < 32; componentShift += 8) {
                if (uint8(actualLane >> componentShift) < uint8(minimumLane >> componentShift)) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @notice Combines two PLATFORM_INFO requirements.
    /// @dev The caller must validate each input first. A cross-policy conflict reverts.
    function mergePlatformInfoPolicies(bytes32 left, bytes32 right) internal pure returns (bytes32 result) {
        uint64 requiredSet = uint64(uint256(left)) | uint64(uint256(right));
        uint64 requiredClear = uint64(uint256(left) >> 64) | uint64(uint256(right) >> 64);
        if ((requiredSet & requiredClear) != 0) {
            revert InvalidAmdSnpPlatformInfoPolicy(bytes32(uint256(requiredSet) | (uint256(requiredClear) << 64)));
        }
        return bytes32(uint256(requiredSet) | (uint256(requiredClear) << 64));
    }

    /// @notice Returns true when PLATFORM_INFO satisfies the packed policy.
    function platformInfoMatches(uint64 actual, bytes32 packedPolicy) internal pure returns (bool) {
        uint64 requiredSet = uint64(uint256(packedPolicy));
        uint64 requiredClear = uint64(uint256(packedPolicy) >> 64);
        return (actual & requiredSet) == requiredSet && (actual & requiredClear) == 0;
    }
}
