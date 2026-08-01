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
        if (!isValidTcb(packedTcb)) revert InvalidAmdSnpTcbValue(packedTcb);
    }

    function isValidTcb(bytes32 packedTcb) internal pure returns (bool) {
        uint256 packed = uint256(packedTcb);
        for (uint256 shift = 0; shift < 256; shift += 64) {
            uint64 lane = uint64((packed >> shift) & TCB_LANE_MASK);
            if ((lane & ~TCB_SUPPORTED_COMPONENT_MASK) != 0) {
                return false;
            }
        }
        return true;
    }

    /// @notice Validates the packed required-set and required-clear PLATFORM_INFO masks.
    function validatePlatformInfoPolicy(bytes32 packedPolicy) internal pure {
        if (!isValidPlatformInfoPolicy(packedPolicy)) {
            revert InvalidAmdSnpPlatformInfoPolicy(packedPolicy);
        }
    }

    function isValidPlatformInfoPolicy(bytes32 packedPolicy) internal pure returns (bool) {
        uint256 packed = uint256(packedPolicy);
        uint64 requiredSet = uint64(packed);
        uint64 requiredClear = uint64(packed >> 64);
        return (packed >> 128) == 0 && (requiredSet & ~SNP_PLATFORM_INFO_SUPPORTED_MASK) == 0
            && (requiredClear & ~SNP_PLATFORM_INFO_SUPPORTED_MASK) == 0 && (requiredSet & requiredClear) == 0;
    }

    /// @notice Returns true when every actual TCB component meets its minimum.
    function tcbMeetsMinimum(bytes32 actual, bytes32 minimum) internal pure returns (bool) {
        uint256 actualValue = uint256(actual);
        uint256 minimumValue = uint256(minimum);
        for (uint256 laneShift = 0; laneShift < 256; laneShift += 64) {
            uint64 actualLane = uint64(actualValue >> laneShift);
            uint64 minimumLane = uint64(minimumValue >> laneShift);
            if (((actualLane | minimumLane) & ~TCB_SUPPORTED_COMPONENT_MASK) != 0) {
                return false;
            }
            for (uint256 componentShift = 0; componentShift < 32; componentShift += 8) {
                if (uint8(actualLane >> componentShift) < uint8(minimumLane >> componentShift)) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @notice Combines two PLATFORM_INFO requirements into a single packed policy.
    /// @dev This helper does not revert so the caller can report invalid input or a conflict
    ///      with its own domain-specific error; `merged` is only meaningful when `ok` is true.
    /// @return ok False when one side requires a bit set that the other requires cleared.
    /// @return merged The union of both required-set masks and of both required-clear masks.
    function tryMergePlatformInfoPolicies(bytes32 left, bytes32 right) internal pure returns (bool ok, bytes32 merged) {
        if (!isValidPlatformInfoPolicy(left) || !isValidPlatformInfoPolicy(right)) {
            return (false, bytes32(0));
        }
        uint64 requiredSet = uint64(uint256(left)) | uint64(uint256(right));
        uint64 requiredClear = uint64(uint256(left) >> 64) | uint64(uint256(right) >> 64);
        merged = bytes32(uint256(requiredSet) | (uint256(requiredClear) << 64));
        ok = (requiredSet & requiredClear) == 0;
    }

    /// @notice Returns true when a CPUID identifies a processor this version supports.
    /// @dev Shared by TeeVerifier (report extraction) and AmdSnpSecurityPolicyRegistry
    ///      (policy admission) so the supported-silicon window is defined in one place.
    ///      Family 0x19 models 0x00-0x0f are Milan and 0x10-0x1f are Genoa. Turin
    ///      (family 0x1a) is not supported. The stepping byte is not constrained here;
    ///      policy is keyed on the exact CPUID including stepping.
    function isSupportedCpuid(uint24 cpuid) internal pure returns (bool) {
        uint8 family = uint8(cpuid >> 16);
        uint8 model = uint8(cpuid >> 8);
        return family == 0x19 && model <= 0x1f;
    }

    /// @notice Returns true when PLATFORM_INFO satisfies the packed policy.
    function platformInfoMatches(uint64 actual, bytes32 packedPolicy) internal pure returns (bool) {
        if (!isValidPlatformInfoPolicy(packedPolicy)) {
            return false;
        }
        uint64 requiredSet = uint64(uint256(packedPolicy));
        uint64 requiredClear = uint64(uint256(packedPolicy) >> 64);
        return (actual & requiredSet) == requiredSet && (actual & requiredClear) == 0;
    }
}
