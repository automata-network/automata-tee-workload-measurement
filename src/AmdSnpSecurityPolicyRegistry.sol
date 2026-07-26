// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    IAmdSnpSecurityPolicyRegistry,
    AmdSnpSecurityPolicy,
    AmdSnpSecurityPolicyUpdate,
    VerifiedTeePolicyInputs
} from "./interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {Attribute, AttributeRequirement} from "./types/Common.sol";
import {
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
    TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM,
    TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
    TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT,
    TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
    TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT,
    TDX_TCB_STATUS_OK,
    TEE_ATTRIBUTE_TRUE
} from "./types/Constants.sol";
import {TEEType} from "./types/Evidence.sol";
import {AmdSnpPolicy} from "./lib/AmdSnpPolicy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title AmdSnpSecurityPolicyRegistry
/// @notice Stores the default AMD SEV-SNP TCB and PLATFORM_INFO policy for each exact CPUID.
contract AmdSnpSecurityPolicyRegistry is IAmdSnpSecurityPolicyRegistry, OwnableUpgradeable, UUPSUpgradeable {
    mapping(uint24 => AmdSnpSecurityPolicy) private _policies;

    uint256[49] private __gap;

    error EmptyPolicyUpdate();
    error InvalidSourceDigest();
    error PolicyUpdatesNotSorted(uint24 previousCpuid, uint24 actualCpuid);
    error UnsupportedCpuid(uint24 cpuid);
    error PolicyNotFound(uint24 cpuid);
    error PolicyNotActive(uint24 cpuid);
    error InvalidPolicyRevision(uint24 cpuid, uint64 actual, uint64 expectedMinimum);
    error PolicyRevisionConflict(uint24 cpuid, uint64 revision);
    error InvalidInactivePolicy(uint24 cpuid, bytes32 minimumTcb, bytes32 platformInfoPolicy);
    error TeeAttributeBaseImageMismatch(bytes32 key, bytes32 declaredValue, bytes32 verifiedValue);
    error TeeAttributeValueNotAllowed(bytes32 key, bytes32 actualValue);
    error TeeAttributePolicyConflict(bytes32 key, bytes32 baseValue, bytes32 workloadValue);
    error AttributeNotFound(bytes32 key);
    error AttributeValueNotAllowed(bytes32 key, bytes32 actualValue);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
    }

    /// @inheritdoc IAmdSnpSecurityPolicyRegistry
    function updatePolicies(AmdSnpSecurityPolicyUpdate[] calldata updates, bytes32 sourceDigest) external onlyOwner {
        uint256 length = updates.length;
        if (length == 0) revert EmptyPolicyUpdate();
        if (sourceDigest == bytes32(0)) revert InvalidSourceDigest();

        uint24 previousCpuid;
        for (uint256 i = 0; i < length; i++) {
            AmdSnpSecurityPolicyUpdate calldata update = updates[i];
            if (i != 0 && update.cpuid <= previousCpuid) {
                revert PolicyUpdatesNotSorted(previousCpuid, update.cpuid);
            }
            previousCpuid = update.cpuid;
            _validateCpuid(update.cpuid);
            _applyUpdate(update, sourceDigest);
        }
    }

    /// @inheritdoc IAmdSnpSecurityPolicyRegistry
    function getPolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy) {
        policy = _policies[cpuid];
        if (policy.revision == 0) revert PolicyNotFound(cpuid);
    }

    /// @inheritdoc IAmdSnpSecurityPolicyRegistry
    function getActivePolicy(uint24 cpuid) external view returns (AmdSnpSecurityPolicy memory policy) {
        policy = _policies[cpuid];
        if (policy.revision == 0) revert PolicyNotFound(cpuid);
        if (!policy.active) revert PolicyNotActive(cpuid);
    }

    /// @inheritdoc IAmdSnpSecurityPolicyRegistry
    function verifyTeePolicy(
        VerifiedTeePolicyInputs calldata inputs,
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) external view {
        _verifyGenericAttributes(profileAttributes, variantAttributes, requirements);

        if (inputs.teeType == TEEType.IntelTDX) {
            _verifyBooleanAttribute(
                TEE_ATTRIBUTE_INTEL_TDX_DEBUG,
                (inputs.enabledTeeAttributes & TEE_ATTRIBUTE_INTEL_TDX_DEBUG_BIT) != 0,
                profileAttributes,
                variantAttributes,
                requirements
            );
            bytes32 baseMask = _effectiveAttribute(
                profileAttributes,
                variantAttributes,
                TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED,
                bytes32(TDX_TCB_STATUS_OK)
            );
            if ((uint256(baseMask) & inputs.intelTdxTcbStatusBit) == 0) {
                revert TeeAttributeBaseImageMismatch(
                    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, baseMask, bytes32(inputs.intelTdxTcbStatusBit)
                );
            }
            bytes32 workloadMask = _requirementOrDefault(
                requirements, TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(TDX_TCB_STATUS_OK)
            );
            if ((uint256(workloadMask) & inputs.intelTdxTcbStatusBit) == 0) {
                revert TeeAttributeValueNotAllowed(
                    TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED, bytes32(inputs.intelTdxTcbStatusBit)
                );
            }
            return;
        }

        AmdSnpSecurityPolicy storage policy = _policies[inputs.amdSevSnpCpuid];
        if (policy.revision == 0) revert PolicyNotFound(inputs.amdSevSnpCpuid);
        if (!policy.active) revert PolicyNotActive(inputs.amdSevSnpCpuid);

        _verifyBooleanAttribute(
            TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG,
            (inputs.enabledTeeAttributes & TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG_BIT) != 0,
            profileAttributes,
            variantAttributes,
            requirements
        );
        _verifyBooleanAttribute(
            TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA,
            (inputs.enabledTeeAttributes & TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA_BIT) != 0,
            profileAttributes,
            variantAttributes,
            requirements
        );

        bytes32 baseTcb = _effectiveAttribute(
            profileAttributes, variantAttributes, TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, policy.minimumTcb
        );
        bytes32 workloadTcb =
            _requirementOrDefault(requirements, TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, policy.minimumTcb);
        if (!AmdSnpPolicy.tcbMeetsMinimum(inputs.amdSevSnpTcbValues, baseTcb)) {
            revert TeeAttributeBaseImageMismatch(
                TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, baseTcb, inputs.amdSevSnpTcbValues
            );
        }
        if (!AmdSnpPolicy.tcbMeetsMinimum(inputs.amdSevSnpTcbValues, workloadTcb)) {
            revert TeeAttributeValueNotAllowed(TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM, inputs.amdSevSnpTcbValues);
        }

        bytes32 basePlatformInfo = _effectiveAttribute(
            profileAttributes,
            variantAttributes,
            TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
            policy.platformInfoPolicy
        );
        bytes32 workloadPlatformInfo = _requirementOrDefault(
            requirements, TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, policy.platformInfoPolicy
        );
        if (!AmdSnpPolicy.platformInfoMatches(inputs.amdSevSnpPlatformInfo, basePlatformInfo)) {
            revert TeeAttributeBaseImageMismatch(
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY,
                basePlatformInfo,
                bytes32(uint256(inputs.amdSevSnpPlatformInfo))
            );
        }
        bytes32 effectiveWorkloadPlatformInfo = _mergePlatformInfoPolicies(basePlatformInfo, workloadPlatformInfo);
        if (!AmdSnpPolicy.platformInfoMatches(inputs.amdSevSnpPlatformInfo, effectiveWorkloadPlatformInfo)) {
            revert TeeAttributeValueNotAllowed(
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, bytes32(uint256(inputs.amdSevSnpPlatformInfo))
            );
        }
    }

    function _applyUpdate(AmdSnpSecurityPolicyUpdate calldata update, bytes32 sourceDigest) private {
        AmdSnpSecurityPolicy storage stored = _policies[update.cpuid];
        bool exists = stored.revision != 0;

        if (!update.active) {
            if (update.minimumTcb != bytes32(0) || update.platformInfoPolicy != bytes32(0)) {
                revert InvalidInactivePolicy(update.cpuid, update.minimumTcb, update.platformInfoPolicy);
            }
            if (!exists) revert PolicyNotFound(update.cpuid);
        } else {
            AmdSnpPolicy.validateTcb(update.minimumTcb);
            AmdSnpPolicy.validatePlatformInfoPolicy(update.platformInfoPolicy);
        }

        if (!exists) {
            if (update.revision == 0) {
                revert InvalidPolicyRevision(update.cpuid, update.revision, 1);
            }
        } else if (update.revision < stored.revision) {
            uint64 expectedMinimum = stored.revision == type(uint64).max ? type(uint64).max : stored.revision + 1;
            revert InvalidPolicyRevision(update.cpuid, update.revision, expectedMinimum);
        } else if (update.revision == stored.revision) {
            bool same = stored.active == update.active
                && (!update.active
                    || (stored.minimumTcb == update.minimumTcb
                        && stored.platformInfoPolicy == update.platformInfoPolicy));
            if (!same) revert PolicyRevisionConflict(update.cpuid, update.revision);
            return;
        }

        if (update.active) {
            stored.minimumTcb = update.minimumTcb;
            stored.platformInfoPolicy = update.platformInfoPolicy;
        }
        stored.sourceDigest = sourceDigest;
        stored.revision = update.revision;
        stored.active = update.active;

        emit AmdSnpSecurityPolicyUpdated(
            update.cpuid, update.revision, update.active, stored.minimumTcb, stored.platformInfoPolicy, sourceDigest
        );
    }

    function _validateCpuid(uint24 cpuid) private pure {
        uint8 family = uint8(cpuid >> 16);
        uint8 model = uint8(cpuid >> 8);
        if (family != 0x19 || model > 0x1f) {
            revert UnsupportedCpuid(cpuid);
        }
    }

    function _verifyBooleanAttribute(
        bytes32 key,
        bool enabled,
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) private pure {
        bytes32 verifiedValue = enabled ? TEE_ATTRIBUTE_TRUE : bytes32(0);
        bytes32 declaredValue = _effectiveAttribute(profileAttributes, variantAttributes, key, bytes32(0));
        if (declaredValue != verifiedValue) {
            revert TeeAttributeBaseImageMismatch(key, declaredValue, verifiedValue);
        }
        if (enabled) {
            for (uint256 i = 0; i < requirements.length; i++) {
                if (requirements[i].key == key) {
                    if (requirements[i].allowedValues.length == 2) return;
                    break;
                }
            }
            revert TeeAttributeValueNotAllowed(key, verifiedValue);
        }
    }

    function _effectiveAttribute(
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        bytes32 key,
        bytes32 defaultValue
    ) private pure returns (bytes32) {
        for (uint256 i = 0; i < variantAttributes.length; i++) {
            if (variantAttributes[i].key == key) return variantAttributes[i].value;
        }
        for (uint256 i = 0; i < profileAttributes.length; i++) {
            if (profileAttributes[i].key == key) return profileAttributes[i].value;
        }
        return defaultValue;
    }

    function _requirementOrDefault(AttributeRequirement[] calldata requirements, bytes32 key, bytes32 defaultValue)
        private
        pure
        returns (bytes32)
    {
        for (uint256 i = 0; i < requirements.length; i++) {
            if (requirements[i].key == key) return requirements[i].allowedValues[0];
        }
        return defaultValue;
    }

    function _verifyGenericAttributes(
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) private pure {
        for (uint256 i = 0; i < requirements.length; i++) {
            bytes32 key = requirements[i].key;
            if (_isTeeAttributeKey(key)) continue;

            (bool found, bytes32 actualValue) = _findEffectiveAttribute(profileAttributes, variantAttributes, key);
            if (!found) revert AttributeNotFound(key);

            bytes32[] calldata allowedValues = requirements[i].allowedValues;
            if (allowedValues.length == 0) continue;

            bool allowed;
            for (uint256 j = 0; j < allowedValues.length; j++) {
                if (actualValue == allowedValues[j]) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) revert AttributeValueNotAllowed(key, actualValue);
        }
    }

    function _findEffectiveAttribute(
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        bytes32 key
    ) private pure returns (bool found, bytes32 value) {
        for (uint256 i = 0; i < variantAttributes.length; i++) {
            if (variantAttributes[i].key == key) {
                return (true, variantAttributes[i].value);
            }
        }
        for (uint256 i = 0; i < profileAttributes.length; i++) {
            if (profileAttributes[i].key == key) return (true, profileAttributes[i].value);
        }
    }

    function _mergePlatformInfoPolicies(bytes32 left, bytes32 right) private pure returns (bytes32) {
        uint64 requiredSet = uint64(uint256(left)) | uint64(uint256(right));
        uint64 requiredClear = uint64(uint256(left) >> 64) | uint64(uint256(right) >> 64);
        if ((requiredSet & requiredClear) != 0) {
            revert TeeAttributePolicyConflict(TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, left, right);
        }
        return bytes32(uint256(requiredSet) | (uint256(requiredClear) << 64));
    }

    function _isTeeAttributeKey(bytes32 key) private pure returns (bool) {
        return key == TEE_ATTRIBUTE_INTEL_TDX_DEBUG || key == TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            || key == TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA || key == TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED
            || key == TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM || key == TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
