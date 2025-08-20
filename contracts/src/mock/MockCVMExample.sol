// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {CVMRegistry} from "../usecases/CVMRegistry.sol";
import {CVMSignature} from "../usecases/bases/CVMSignature.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {Pubkey, Crypto} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";
import {TPM_ALG_ECDSA} from "@automata-network/automata-tpm-attestation/types/Constants.sol";

contract MockCVMExample is CVMSignature {
    CVMRegistry public immutable cvmRegistry;
    address public owner;
    mapping(bytes32 goldenMeasurementHash => bool) public goldenMeasurements;

    constructor(address _cvnRegistry) {
        owner = msg.sender;
        cvmRegistry = CVMRegistry(_cvnRegistry);
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

    /**
     * @notice Checks if a provided a CVM is registered with valid measurements
     */
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
        Pubkey memory cvmIdentityKey = cvmRegistry.getCvmIdentity(cvmIdentityHash);
        address verifier = cvmIdentityKey.sigScheme == TPM_ALG_ECDSA ? cvmRegistry.tpmAttestation().p256() : address(0);
        verified = cvmIdentityKey.verifySignature(_generateMessage(message), signature, verifier);
    }
}
