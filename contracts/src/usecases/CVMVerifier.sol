// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {IWorkloadVerifier, WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import {CloudType, TEEType, TeeReportType} from "../lib/LibTEE.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CVMVerifier is OwnableUpgradeable, UUPSUpgradeable {
    IWorkloadVerifier public workloadVerifier;
    uint256[47] private __gap;

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Only the owner can authorize an upgrade.
     * @param newImplementation The address of the new implementation.
     */
    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
    }

    function initialize(address _intialOwner, address _workloadVerifier) external initializer {
        workloadVerifier = IWorkloadVerifier(_workloadVerifier);
        __Ownable_init(_intialOwner);
    }

    function verifyCvmWorkload(
        bytes32 userDataHash,
        CloudType cloudType,
        TEEType teeType,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata workloadReport
    ) external payable {
        workloadVerifier.verifyAttestationHash(
            userDataHash, teeType, teeReportType, cloudType, teeAttestationReport, workloadReport
        );
    }
}
