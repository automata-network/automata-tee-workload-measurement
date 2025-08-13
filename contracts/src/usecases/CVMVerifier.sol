// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {IWorkloadVerifier, WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import {CloudType, TEEType, TeeReportType, GoldenMeasurement} from "../lib/LibTEE.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CVMVerifier is OwnableUpgradeable, UUPSUpgradeable {
    IWorkloadVerifier public workloadVerifier;
    mapping(bytes32 goldenMeasurementHashes => bool registered) private _goldenMeasurementHashes;
    uint256[47] private __gap;

    event GoldenMeasurementAdded(bytes32 indexed goldenMeasurementHash);

    event GoldenMeasurementRemoved(bytes32 indexed goldenMeasurementHash);

    constructor() {
        _disableInitializers();
    }

    // c83937d4
    error GM_NOT_FOUND(bytes32 gmHash);
    // c7ebe8a4
    error GM_ALREADY_REGISTERED(bytes32 gmHash);

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

    function registerGm(GoldenMeasurement calldata goldenMeasurement) external onlyOwner returns (bytes32 gmHash) {
        gmHash = goldenMeasurement.digest();

        if (_goldenMeasurementHashes[gmHash]) {
            revert GM_ALREADY_REGISTERED(gmHash);
        }

        _goldenMeasurementHashes[gmHash] = true;
        emit GoldenMeasurementAdded(gmHash);
    }

    function deregisterGm(bytes32 gmHash) external onlyOwner {
        if (!_goldenMeasurementHashes[gmHash]) {
            revert GM_NOT_FOUND(gmHash);
        }

        delete _goldenMeasurementHashes[gmHash];
        emit GoldenMeasurementRemoved(gmHash);
    }

    function verifyCvmWorkload(
        bytes32 userDataHash,
        CloudType cloudType,
        TEEType teeType,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata workloadReport
    ) external payable {
        bytes32 gmHash = workloadVerifier.verifyAttestationHash(
            userDataHash, teeType, teeReportType, cloudType, teeAttestationReport, workloadReport
        );

        if (!_goldenMeasurementHashes[gmHash]) {
            revert GM_NOT_FOUND(gmHash);
        }
    }
}
