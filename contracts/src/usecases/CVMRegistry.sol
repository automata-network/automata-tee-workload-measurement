// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {IWorkloadVerifier, WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import {ICVMRegistry, CVMConfig} from "../interfaces/ICVMRegistry.sol";
import {CloudType, TEEType, TeeReportType, Measurement, TEEVerifiedData} from "../lib/LibTEE.sol";
import {BytesUtils} from "../lib/BytesUtils.sol";

import {Pubkey, Crypto} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";
import {TPM_ALG_SHA256, TPM_ALG_ECDSA} from "@automata-network/automata-tpm-attestation/types/Constants.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract CVMRegistry is ICVMRegistry, OwnableUpgradeable, UUPSUpgradeable {
    using BytesUtils for bytes;

    IWorkloadVerifier public immutable workloadVerifier;
    ITpmAttestation public immutable tpmAttestation;

    // min CSP limitations (Azure: 50 bytes; GCP: 64 bytes; AWS: 66 bytes)
    uint8 constant TPM_DATA_MAX_LENGTH = 50;
    /// The default TTL (in seconds) for TEE Reports (30 days, tentative)
    uint64 constant DEFAULT_TEE_TTL = 2_592_000;
    /// The default TTL (in seconds) for TPM Quotes (60 days, tentative)
    uint64 constant DEFAULT_TPM_TTL = 5_184_000;
    /// Mapping between a given CVM and its config
    mapping(bytes32 cvmIdentityHash => CVMConfig) _configs;
    mapping(bytes32 cvmIdentityHash => uint256) _nonces;
    uint256[47] private __gap;

    constructor(address _workloadVerifier) {
        workloadVerifier = IWorkloadVerifier(_workloadVerifier);
        tpmAttestation = workloadVerifier.tpmAttestation();
        _disableInitializers();
    }

    modifier onlyRegistered(bytes32 cvmIdentityHash) {
        if (!hasRegistered(cvmIdentityHash)) {
            revert CVM_NOT_REGISTERED();
        }
        _;
    }

    /**
     * @notice Only the owner can authorize an upgrade.
     * @param newImplementation The address of the new implementation.
     */
    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
    }

    function initialize(address _intialOwner) external initializer {
        __Ownable_init(_intialOwner);
    }

    function attestCvm(
        CloudType cloudType,
        TEEType teeType,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external override returns (Measurement memory measurements) {
        // Step 0: Preliminary Checks
        bytes32 identity = _computeCvmIdentityHash(wc.cvmIdentity);
        CVMConfig storage config = _configs[identity];

        if (!hasRegistered(identity)) {
            config.teeType = teeType;
            config.cloudType = cloudType;
            config.teeTTL = DEFAULT_TEE_TTL;
            config.tpmTTL = DEFAULT_TPM_TTL;
        }

        // Step 1: Verify attestation reports and the workload TPM measurements
        bytes memory tpmExtraData;
        (config.teeAttestationOutput, measurements, tpmExtraData) =
            workloadVerifier.verifyAttestation(config.teeType, teeReportType, config.cloudType, teeAttestationReport, wc);

        // Step 2: Check whether the TPM contains the CVM identity
        bytes32 tpmIdentity = _parseIdentityFromTpmData(tpmExtraData);
        if (tpmIdentity != identity) {
            revert CVM_IDENTITY_MISMATCH(identity, tpmIdentity);
        }

        // Step 3: Register the identity
        uint64 currentTimestamp = uint64(block.timestamp);
        config.cvmIdentity = wc.cvmIdentity;
        config.teeRecentTimestamp = currentTimestamp;
        config.tpmRecentTimestamp = currentTimestamp;
        config.measurementHash = measurements.digest();

        emit CVMUpdated(identity);
    }

    function reattestCvmWithTpm(bytes32 cvmIdentityHash, bytes calldata signature, WorkloadCollaterals calldata wc)
        external
        override
        onlyRegistered(cvmIdentityHash)
        returns (Measurement memory measurements)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];

        // Step 1: Verify the signature against the CVM identity
        Pubkey memory cvmIdentity = config.cvmIdentity;
        if (cvmIdentity.hashAlgo != TPM_ALG_SHA256) {
            revert UNSUPPORTED_HASH_ALGORITHM(cvmIdentity.hashAlgo);
        }
        {
            bytes memory message = abi.encodePacked(
                "CVM_WORKLOAD_REATTEST_TPM",
                uint16(block.chainid),
                address(this),
                _nonces[cvmIdentityHash]++,
                sha256(wc.tpmQuote)
            );
            address verifier = cvmIdentity.sigScheme == TPM_ALG_ECDSA ? tpmAttestation.p256() : address(0);
            bool verified = cvmIdentity.verifySignature(message, signature, verifier);
            if (!verified) {
                revert INVALID_SIGNATURE();
            }
        }

        // Step 2: Verify the TPM quote and measurement
        CloudType cloudType = config.cloudType;
        bool tpmVerified;
        string memory err;
        if (cloudType == CloudType.Azure) {
            Pubkey memory tpmAk = workloadVerifier.parseVarKeyJson(string(wc.akPub));
            (tpmVerified, err) = tpmAttestation.verifyTpmQuote(wc.tpmQuote, wc.tpmSignature, tpmAk);
        } else if (cloudType == CloudType.GCP) {
            (tpmVerified, err) = tpmAttestation.verifyTpmQuote(wc.tpmQuote, wc.tpmSignature, wc.certs);
        }
        if (!tpmVerified) {
            revert INVALID_TPM_QUOTE(err);
        }

        // Step 3: Check PCR Measurement and extract TPM Extra Data
        (bool pcrMeasuredChecked, bytes memory extraData) = tpmAttestation.checkPcrMeasurements(wc.tpmQuote, wc.pcrs);
        if (!pcrMeasuredChecked) {
            revert INVALID_TPM_MEASUREMENT(string(extraData));
        }

        // Step 4: Get the final measurement
        TEEVerifiedData memory teeData = workloadVerifier.parseTeeOutput(config.teeType, config.teeAttestationOutput);
        measurements =
            Measurement({pcrs: tpmAttestation.toFinalMeasurement(wc.pcrs), tdx: teeData.tdx, snp: teeData.snp});

        // Step 5: If Extra Data contains a different identity hash from the current CVM Identity
        // that means a key rotation is occurring, check whether it matches with the new identity
        // provided as workload collateral
        Pubkey memory wcIdentity = wc.cvmIdentity;
        bytes32 wcIdentityHash = _computeCvmIdentityHash(wcIdentity);
        uint64 currentTimestamp = uint64(block.timestamp);
        if (wcIdentityHash != cvmIdentityHash) {
            // First, check TPM data matches with the new identity hash
            bytes32 tpmIdentityHash = _parseIdentityFromTpmData(extraData);
            if (tpmIdentityHash != wcIdentityHash) {
                revert CVM_IDENTITY_MISMATCH(tpmIdentityHash, wcIdentityHash);
            }
            _rotateCvmIdentity(cvmIdentityHash, wcIdentityHash, wcIdentity, currentTimestamp, measurements.digest());
            emit CVMUpdated(wcIdentityHash);
        } else {
            config.measurementHash = measurements.digest();
            config.tpmRecentTimestamp = currentTimestamp;
            emit CVMUpdated(cvmIdentityHash);
        }
    }

    function setCollateralTTL(bytes32 cvmIdentityHash, uint64 teeTTL, uint64 tpmTTL, bytes calldata signature)
        external
        override
        onlyRegistered(cvmIdentityHash)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];

        // Verify the signature against CVM Identity
        Pubkey memory cvmIdentity = config.cvmIdentity;
        if (cvmIdentity.hashAlgo != TPM_ALG_SHA256) {
            revert UNSUPPORTED_HASH_ALGORITHM(cvmIdentity.hashAlgo);
        }
        {
            bytes memory message = abi.encodePacked(
                "CVM_WORKLOAD_TTL_CONFIG",
                uint16(block.chainid),
                address(this),
                _nonces[cvmIdentityHash]++,
                teeTTL,
                tpmTTL
            );
            address verifier = cvmIdentity.sigScheme == TPM_ALG_ECDSA ? tpmAttestation.p256() : address(0);
            bool verified = cvmIdentity.verifySignature(message, signature, verifier);
            if (!verified) {
                revert INVALID_SIGNATURE();
            }
        }

        config.teeTTL = teeTTL;
        config.tpmTTL = tpmTTL;
        emit CVMTTLUpdated(cvmIdentityHash);
    }

    function nonces(bytes32 cvmIdentityHash) external view override onlyRegistered(cvmIdentityHash) returns (uint256) {
        return _nonces[cvmIdentityHash];
    }

    function hasRegistered(bytes32 cvmIdentityHash) public view override returns (bool) {
        return _configs[cvmIdentityHash].cloudType != CloudType.Unset;
    }

    function checkTEEValidity(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (bool valid)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];
        valid = (block.timestamp - config.teeRecentTimestamp) < config.teeTTL;
    }

    function checkTPMValidity(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (bool valid)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];
        valid = (block.timestamp - config.tpmRecentTimestamp) < config.tpmTTL;
    }

    function getMeasurementHash(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (bytes32 hash)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];
        hash = config.measurementHash;
    }

    function getCvmIdentity(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (Pubkey memory identity)
    {
        CVMConfig storage config = _configs[cvmIdentityHash];
        identity = config.cvmIdentity;
    }

    function getCvmConfig(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (CVMConfig memory config)
    {
        config = _configs[cvmIdentityHash];
    }

    function _computeCvmIdentityHash(Pubkey memory cvmIdentity) private pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(cvmIdentity.sigScheme, cvmIdentity.curve, cvmIdentity.hashAlgo, cvmIdentity.data)
        );
    }

    /// @dev the TPM data consists of
    /// uint8 magic_prefix || bytes32 cvmIdentityHash || bytes nonce
    function _parseIdentityFromTpmData(bytes memory tpmExtraData) private pure returns (bytes32 cvmIdentityHash) {
        if (tpmExtraData.length > TPM_DATA_MAX_LENGTH) {
            revert INVALID_TPM_DATA_LENGTH();
        }
        cvmIdentityHash = bytes32(tpmExtraData.substring(1, 32));
    }

    function _rotateCvmIdentity(
        bytes32 oldCvmIdentityHash,
        bytes32 newCvmIdentityHash,
        Pubkey memory newCvmIdentity,
        uint64 tpmRecentTimestamp,
        bytes32 measurementHash
    ) private {
        CVMConfig storage oldConfig = _configs[oldCvmIdentityHash];
        CVMConfig storage newConfig = _configs[newCvmIdentityHash];

        // Copy all fields from oldConfig to newConfig
        newConfig.cloudType = oldConfig.cloudType;
        newConfig.teeType = oldConfig.teeType;
        newConfig.teeTTL = oldConfig.teeTTL;
        newConfig.tpmTTL = oldConfig.tpmTTL;
        newConfig.teeRecentTimestamp = oldConfig.teeRecentTimestamp;
        newConfig.teeAttestationOutput = oldConfig.teeAttestationOutput;
        newConfig.cvmIdentity = newCvmIdentity;
        newConfig.tpmRecentTimestamp = tpmRecentTimestamp;
        newConfig.measurementHash = measurementHash;

        delete _configs[oldCvmIdentityHash];
    }
}
