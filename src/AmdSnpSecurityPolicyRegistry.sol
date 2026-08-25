// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {
    IAmdSnpSecurityPolicyRegistry,
    AmdSnpSecurityPolicy,
    AmdSnpSecurityPolicyUpdate
} from "./interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
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

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
