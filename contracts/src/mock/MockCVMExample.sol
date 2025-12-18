// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ICVMRegistry, CVMIdentity} from "../interfaces/ICVMRegistry.sol";
import {CVMSignature} from "../usecases/bases/CVMSignature.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, SignatureAlgorithm, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {LibX509Verify} from "@automata-network/automata-tpm-attestation/lib/LibX509Verify.sol";
import {TPMConstants} from "@automata-network/automata-tpm-attestation/types/TPMConstants.sol";

contract MockCVMExample is CVMSignature {
    using LibX509Verify for CertPubkey;
    ICVMRegistry public immutable cvmRegistry;
    address public owner;
    mapping(bytes32 goldenMeasurementHash => bool) public goldenMeasurements;

    constructor(address _cvnRegistry, address _p256Verifier) {
        owner = msg.sender;
        P256_VERIFIER = _p256Verifier;
        cvmRegistry = ICVMRegistry(_cvnRegistry);
    }

    event GoldenMeasurementRegistered(bytes32 indexed measurementHash);
    event GoldenMeasurementRemoved(bytes32 indexed measurementHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    function addGoldenMeasurement(bytes32 measurementHash) external onlyOwner {
        require(!goldenMeasurements[measurementHash], "Measurement already registered");
        goldenMeasurements[measurementHash] = true;
        emit GoldenMeasurementRegistered(measurementHash);
    }

    function removeGoldenMeasurement(bytes32 measurementHash) external onlyOwner {
        require(goldenMeasurements[measurementHash], "Measurement not registered");
        delete goldenMeasurements[measurementHash];
        emit GoldenMeasurementRemoved(measurementHash);
    }

    /// @notice Checks if a provided a CVM is registered with valid measurements
    function checkCvmIsValid(bytes32 cvmIdentityHash) public view returns (bool) {
        bytes32 measurementHash = cvmRegistry.getMeasurementHash(cvmIdentityHash);
        return goldenMeasurements[measurementHash];
    }

    function checkCVMSignature(bytes32 cvmIdentityHash, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        // Step 1: Check CVM Identity is registered and contained valid measurements
        bool cvmMeasurementValid = checkCvmIsValid(cvmIdentityHash);
        if (!cvmMeasurementValid) {
            return false;
        }

        // Step 2: Verify CVM Signature
        CVMIdentity memory cvmIdentity = cvmRegistry.getCvmIdentity(cvmIdentityHash);
        verified = _verifySignature(cvmIdentity, signature, message);
    }
}
