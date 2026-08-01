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
    TEE_ATTRIBUTE_TRUE,
    TEE_ATTRIBUTE_FALSE
} from "./types/Constants.sol";
import {TEEType} from "./types/Evidence.sol";
import {AmdSnpPolicy} from "./lib/AmdSnpPolicy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title AmdSnpSecurityPolicyRegistry
/// @notice Stores AMD SEV-SNP TCB, PLATFORM_INFO, and mitigation-vector policy for each exact CPUID.
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
    error PolicyRevisionMismatch(uint24 cpuid, uint64 actual, uint64 expected);
    error PolicyRevisionConflict(uint24 cpuid, uint64 revision);
    error InvalidInactivePolicy(
        uint24 cpuid,
        bytes32 minimumTcb,
        bytes32 platformInfoPolicy,
        uint64 requiredLaunchMitigationVector,
        uint64 requiredCurrentMitigationVector
    );
    error SnpMitigationPolicyRequiresReportVersion(uint32 actualVersion, uint32 requiredVersion);
    error SnpLaunchMitigationVectorMissing(uint64 requiredMask, uint64 actual);
    error SnpCurrentMitigationVectorMissing(uint64 requiredMask, uint64 actual);
    error TeeAttributeBaseImageMismatch(bytes32 key, bytes32 declaredValue, bytes32 verifiedValue);
    error TeeAttributeValueNotAllowed(bytes32 key, bytes32 actualValue);
    error TeeAttributePolicyConflict(bytes32 key, bytes32 baseValue, bytes32 workloadValue);
    error AttributeNotFound(bytes32 key);
    error AttributeValueNotAllowed(bytes32 key, bytes32 actualValue);
    error EmptyTeeAttributeRequirement(bytes32 key);
    error InvalidPackedTeeAttributeRequirementLength(bytes32 key, uint256 actualLength);

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
        if (
            (policy.requiredLaunchMitigationVector != 0 || policy.requiredCurrentMitigationVector != 0)
                && inputs.amdSevSnpReportVersion != 5
        ) {
            revert SnpMitigationPolicyRequiresReportVersion(inputs.amdSevSnpReportVersion, 5);
        }
        if (
            inputs.amdSevSnpLaunchMitigationVector & policy.requiredLaunchMitigationVector
                != policy.requiredLaunchMitigationVector
        ) {
            revert SnpLaunchMitigationVectorMissing(
                policy.requiredLaunchMitigationVector, inputs.amdSevSnpLaunchMitigationVector
            );
        }
        if (
            inputs.amdSevSnpCurrentMitigationVector & policy.requiredCurrentMitigationVector
                != policy.requiredCurrentMitigationVector
        ) {
            revert SnpCurrentMitigationVectorMissing(
                policy.requiredCurrentMitigationVector, inputs.amdSevSnpCurrentMitigationVector
            );
        }

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
        (bool merged, bytes32 effectiveWorkloadPlatformInfo) =
            AmdSnpPolicy.tryMergePlatformInfoPolicies(basePlatformInfo, workloadPlatformInfo);
        if (!merged) {
            revert TeeAttributePolicyConflict(
                TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY, basePlatformInfo, workloadPlatformInfo
            );
        }
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
            if (
                update.minimumTcb != bytes32(0) || update.platformInfoPolicy != bytes32(0)
                    || update.requiredLaunchMitigationVector != 0 || update.requiredCurrentMitigationVector != 0
            ) {
                revert InvalidInactivePolicy(
                    update.cpuid,
                    update.minimumTcb,
                    update.platformInfoPolicy,
                    update.requiredLaunchMitigationVector,
                    update.requiredCurrentMitigationVector
                );
            }
            if (!exists) revert PolicyNotFound(update.cpuid);
        } else {
            AmdSnpPolicy.validateTcb(update.minimumTcb);
            AmdSnpPolicy.validatePlatformInfoPolicy(update.platformInfoPolicy);
        }

        if (exists && update.revision == stored.revision) {
            bool same = stored.active == update.active
                && (!update.active
                    || (stored.minimumTcb == update.minimumTcb
                        && stored.platformInfoPolicy == update.platformInfoPolicy
                        && stored.requiredLaunchMitigationVector == update.requiredLaunchMitigationVector
                        && stored.requiredCurrentMitigationVector == update.requiredCurrentMitigationVector));
            if (!same) revert PolicyRevisionConflict(update.cpuid, update.revision);
            return;
        }

        if (stored.revision != update.expectedRevision) {
            revert PolicyRevisionMismatch(update.cpuid, stored.revision, update.expectedRevision);
        }

        if (update.revision == 0 || update.revision <= stored.revision) {
            uint64 expectedMinimum = stored.revision == type(uint64).max ? type(uint64).max : stored.revision + 1;
            revert InvalidPolicyRevision(update.cpuid, update.revision, expectedMinimum);
        }

        if (update.active) {
            stored.minimumTcb = update.minimumTcb;
            stored.platformInfoPolicy = update.platformInfoPolicy;
            stored.requiredLaunchMitigationVector = update.requiredLaunchMitigationVector;
            stored.requiredCurrentMitigationVector = update.requiredCurrentMitigationVector;
        }
        stored.sourceDigest = sourceDigest;
        stored.revision = update.revision;
        stored.active = update.active;

        // Report what this update applied, not what storage still holds. A deactivation must
        // supply zeros and keeps the previous values in the record for audit history, so
        // reading them back here would misreport the change to log consumers.
        emit AmdSnpSecurityPolicyUpdated(
            update.cpuid,
            update.revision,
            update.active,
            update.minimumTcb,
            update.platformInfoPolicy,
            update.requiredLaunchMitigationVector,
            update.requiredCurrentMitigationVector,
            sourceDigest
        );
    }

    function _validateCpuid(uint24 cpuid) private pure {
        if (!AmdSnpPolicy.isSupportedCpuid(cpuid)) {
            revert UnsupportedCpuid(cpuid);
        }
    }

    /// @dev Both legs must accept the verified state. The base image declares it exactly; the
    ///      workload must list it among the requirement's allowed values. The allowed values are
    ///      compared by value rather than inferred from the array's length, so the result does
    ///      not depend on WorkloadRegistry's canonical `[false]` / `[false, true]` encoding.
    function _verifyBooleanAttribute(
        bytes32 key,
        bool enabled,
        Attribute[] calldata profileAttributes,
        Attribute[] calldata variantAttributes,
        AttributeRequirement[] calldata requirements
    ) private pure {
        bytes32 verifiedValue = enabled ? TEE_ATTRIBUTE_TRUE : TEE_ATTRIBUTE_FALSE;
        bytes32 declaredValue = _effectiveAttribute(profileAttributes, variantAttributes, key, TEE_ATTRIBUTE_FALSE);
        if (declaredValue != verifiedValue) {
            revert TeeAttributeBaseImageMismatch(key, declaredValue, verifiedValue);
        }
        for (uint256 i = 0; i < requirements.length; i++) {
            if (requirements[i].key != key) continue;
            bytes32[] calldata allowedValues = requirements[i].allowedValues;
            if (allowedValues.length == 0) revert EmptyTeeAttributeRequirement(key);
            for (uint256 j = 0; j < allowedValues.length; j++) {
                if (allowedValues[j] == verifiedValue) return;
            }
            revert TeeAttributeValueNotAllowed(key, verifiedValue);
        }
        // No explicit requirement. The workload opted into nothing, so only the disabled
        // state is acceptable.
        if (enabled) revert TeeAttributeValueNotAllowed(key, verifiedValue);
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

    /// @dev Resolves the workload's explicit value for a packed reserved attribute. A workload
    ///      that states a requirement on one of these keys must name the value it requires, so an
    ///      allowed set must contain exactly one value rather than silently selecting or
    ///      substituting a value — the
    ///      "empty array = any value accepted" convention on `AttributeRequirement` applies to
    ///      ordinary metadata keys only. Omitting the requirement entirely is how a workload
    ///      defers to the registry default. `WorkloadRegistry._validateRequirements` already
    ///      rejects this shape at registration; the check keeps a direct caller of
    ///      `verifyTeePolicy` from being handed a default it never asked for.
    function _requirementOrDefault(AttributeRequirement[] calldata requirements, bytes32 key, bytes32 defaultValue)
        private
        pure
        returns (bytes32)
    {
        for (uint256 i = 0; i < requirements.length; i++) {
            if (requirements[i].key != key) continue;
            bytes32[] calldata allowedValues = requirements[i].allowedValues;
            if (allowedValues.length == 0) revert EmptyTeeAttributeRequirement(key);
            if (allowedValues.length != 1) {
                revert InvalidPackedTeeAttributeRequirementLength(key, allowedValues.length);
            }
            return allowedValues[0];
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

    function _isTeeAttributeKey(bytes32 key) private pure returns (bool) {
        return key == TEE_ATTRIBUTE_INTEL_TDX_DEBUG || key == TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG
            || key == TEE_ATTRIBUTE_AMD_SEV_SNP_MIGRATE_MA || key == TEE_ATTRIBUTE_INTEL_TDX_TCB_STATUS_ALLOWED
            || key == TEE_ATTRIBUTE_AMD_SEV_SNP_TCB_MINIMUM || key == TEE_ATTRIBUTE_AMD_SEV_SNP_PLATFORM_INFO_POLICY;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
