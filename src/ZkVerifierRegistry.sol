// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IZkVerifierRegistry} from "./interfaces/registries/IZkVerifierRegistry.sol";
import {VerificationBackendType} from "./types/Evidence.sol";
import {ZkProofType, ZkProgramConfig} from "./types/Zk.sol";

/// @title ZkVerifierRegistry
/// @notice Resolves one exact proof type, backend, and program identifier to a typed verifier adapter.
contract ZkVerifierRegistry is IZkVerifierRegistry, OwnableUpgradeable, UUPSUpgradeable {
    error ZeroVerifierAdapter();
    error ZkProgramNotEnabled(
        ZkProofType proofType, VerificationBackendType verificationBackendType, bytes32 programIdentifier
    );

    mapping(
        ZkProofType proofType
            => mapping(
            VerificationBackendType verificationBackendType
                => mapping(bytes32 programIdentifier => ZkProgramConfig config)
        )
    ) public zkProgramConfigs;

    uint256[49] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
    }

    function setZkProgramConfig(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier,
        address verifierAdapter,
        bool enabled
    ) external onlyOwner {
        if (verifierAdapter == address(0)) revert ZeroVerifierAdapter();

        ZkProgramConfig storage stored = zkProgramConfigs[proofType][verificationBackendType][programIdentifier];
        address oldVerifierAdapter = stored.verifierAdapter;
        bool oldEnabled = stored.enabled;
        stored.verifierAdapter = verifierAdapter;
        stored.enabled = enabled;

        emit ZkProgramConfigUpdated(
            proofType,
            verificationBackendType,
            programIdentifier,
            oldVerifierAdapter,
            verifierAdapter,
            oldEnabled,
            enabled
        );
    }

    function getZkProgramConfig(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier
    ) external view returns (ZkProgramConfig memory config) {
        return zkProgramConfigs[proofType][verificationBackendType][programIdentifier];
    }

    function resolveVerifierAdapter(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier
    ) external view returns (address verifierAdapter) {
        ZkProgramConfig storage config = zkProgramConfigs[proofType][verificationBackendType][programIdentifier];
        if (!config.enabled || config.verifierAdapter == address(0)) {
            revert ZkProgramNotEnabled(proofType, verificationBackendType, programIdentifier);
        }
        return config.verifierAdapter;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
