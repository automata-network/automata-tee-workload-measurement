// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {VerificationBackendType} from "../../types/Evidence.sol";
import {ZkProofType, ZkProgramConfig} from "../../types/Zk.sol";

interface IZkVerifierRegistry {
    event ZkProgramConfigUpdated(
        ZkProofType indexed proofType,
        VerificationBackendType indexed verificationBackendType,
        bytes32 indexed programIdentifier,
        address oldVerifierAdapter,
        address newVerifierAdapter,
        bool oldEnabled,
        bool newEnabled
    );

    function setZkProgramConfig(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier,
        address verifierAdapter,
        bool enabled
    ) external;

    function getZkProgramConfig(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier
    ) external view returns (ZkProgramConfig memory config);

    function resolveVerifierAdapter(
        ZkProofType proofType,
        VerificationBackendType verificationBackendType,
        bytes32 programIdentifier
    ) external view returns (address verifierAdapter);
}
