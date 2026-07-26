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

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
