// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.20;

import {IWorkloadVerifier, WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import {ICVMRegistry, CVMConfig, CVMIdentity, CVMIdentityCertification} from "../interfaces/ICVMRegistry.sol";
import {CloudType, TEEType, TeeReportType, Measurement, TEEVerifiedData} from "../lib/LibTEE.sol";

import {CertPubkey, SignatureAlgorithm} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {TPMConstants} from "@automata-network/automata-tpm-attestation/types/TPMConstants.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {CVMShared} from "./bases/CVMShared.sol";

contract CVMRegistry is ICVMRegistry, OwnableUpgradeable, UUPSUpgradeable {
    IWorkloadVerifier public immutable workloadVerifier;
    ITpmAttestation public immutable tpmAttestation;

    /// The default TTL (in seconds) for TEE Reports (30 days, tentative)
    uint64 constant DEFAULT_TEE_TTL = 2_592_000;

    /// Contract States:

    /// Mapping between a given CVM and its config
    mapping(bytes32 cvmIdentityHash => CVMConfig) _configs;
    /// Prevents TEE Report replays
    mapping(bytes32 teeHash => bool used) _usedTeeReports;
    /// Prevents TPM Report replays
    mapping(bytes32 tpmHash => bool used) _usedTpmQuotes;
    /// Flags CVM Identity that were rotated out and revoked
    mapping(bytes32 cvmIdentityHash => bool revoked) _revokedCvmIdentities;
    /// Mapping between a given CVM TPM AK and the current CVMIdentity
    /// Ensures only one CVM can hold at most one CVM identity at any time
    mapping(bytes32 akHash => bytes32 cvmIdentity) _akBindings;

    uint256[44] private __gap;

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

    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
    }

    function initialize(address _initialOwner) external reinitializer(3) {
        __Ownable_init(_initialOwner);
    }

    function registerCvm(
        CloudType cloudType,
        TEEType teeType,
        uint64 teeTTL,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        CVMIdentity calldata cvmIdentity,
        CVMIdentityCertification calldata cvmCertification,
        WorkloadCollaterals calldata wc
    ) external override returns (Measurement memory measurements) {
        CertPubkey memory pubkey = CVMShared.extractPubkeyFromTpmtPublic(cvmIdentity.tpmtPublic);
        bytes32 identity = _computeKeyHash(pubkey, cvmIdentity.sigAlgo);

        if (_revokedCvmIdentities[identity]) {
            revert CVM_IDENTITY_REVOKED(identity);
        }
        if (hasRegistered(identity)) {
            revert CVM_ALREADY_REGISTERED(identity);
        }

        bytes32 teeReportHash = keccak256(teeAttestationReport);
        if (_usedTeeReports[teeReportHash]) {
            revert TEE_REPORT_ALREADY_USED(teeReportHash);
        }

        bytes32 tpmQuoteHash = keccak256(wc.tpmQuote);
        if (_usedTpmQuotes[tpmQuoteHash]) {
            revert TPM_QUOTE_ALREADY_USED(tpmQuoteHash);
        }

        bytes memory teeOutput;
        TEEVerifiedData memory teeVerifiedData;
        (teeOutput, teeVerifiedData, measurements) =
            workloadVerifier.verifyAttestation(teeType, teeReportType, cloudType, teeAttestationReport, wc);

        /// @dev for the sole purpose of AK tracking, we do not care about the actual signature algorithm used
        /// @dev the signature algorithm of AK is usually dependent on parameters specified in TPMS_ATTEST structure
        SignatureAlgorithm memory akSigAlgoNull =
            SignatureAlgorithm({scheme: TPMConstants.TPM_ALG_NULL, hashAlgo: TPMConstants.TPM_ALG_NULL});
        bytes32 akHash = _computeKeyHash(teeVerifiedData.akPub, akSigAlgoNull);
        bytes32 existingBinding = _akBindings[akHash];
        if (existingBinding != bytes32(0)) {
            revert AK_ALREADY_BOUND(akHash, existingBinding);
        }

        tpmAttestation.verifyTpmKeyCertification(
            cvmCertification.certInfo,
            cvmCertification.akCertificationSig,
            cvmIdentity.tpmtPublic,
            teeVerifiedData.akPub,
            ""
        );

        _usedTeeReports[teeReportHash] = true;
        _usedTpmQuotes[tpmQuoteHash] = true;
        _akBindings[akHash] = identity;

        uint64 ttl = teeTTL > 0 ? teeTTL : DEFAULT_TEE_TTL;
        CVMConfig storage config = _configs[identity];
        config.teeType = teeType;
        config.cloudType = cloudType;
        config.expiredAt = uint64(block.timestamp) + ttl;
        config.measurementHash = measurements.digest();
        config.cvmIdentity = cvmIdentity;
        config.tpmAk = teeVerifiedData.akPub;
        config.teeAttestationOutput = teeOutput;

        emit CVMRegistered(identity);
    }

    function refreshCvm(
        bytes32 cvmIdentityHash,
        uint64 teeTTL,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external override onlyRegistered(cvmIdentityHash) returns (Measurement memory measurements) {
        CVMConfig storage config = _configs[cvmIdentityHash];

        bytes32 teeReportHash = keccak256(teeAttestationReport);
        if (_usedTeeReports[teeReportHash]) {
            revert TEE_REPORT_ALREADY_USED(teeReportHash);
        }

        bytes32 tpmQuoteHash = keccak256(wc.tpmQuote);
        if (_usedTpmQuotes[tpmQuoteHash]) {
            revert TPM_QUOTE_ALREADY_USED(tpmQuoteHash);
        }

        bytes memory teeOutput;
        TEEVerifiedData memory teeVerifiedData;
        (teeOutput, teeVerifiedData, measurements) = workloadVerifier.verifyAttestation(
            config.teeType, teeReportType, config.cloudType, teeAttestationReport, wc
        );

        /// @dev for the sole purpose of AK tracking, we do not care about the actual signature algorithm used
        /// @dev the signature algorithm of AK is usually dependent on parameters specified in TPMS_ATTEST structure
        SignatureAlgorithm memory akSigAlgoNull =
            SignatureAlgorithm({scheme: TPMConstants.TPM_ALG_NULL, hashAlgo: TPMConstants.TPM_ALG_NULL});
        bytes32 akHash = _computeKeyHash(teeVerifiedData.akPub, akSigAlgoNull);
        bytes32 boundIdentity = _akBindings[akHash];
        if (boundIdentity != cvmIdentityHash) {
            revert AK_BINDING_MISMATCH(akHash, cvmIdentityHash, boundIdentity);
        }

        _usedTeeReports[teeReportHash] = true;
        _usedTpmQuotes[tpmQuoteHash] = true;

        uint64 ttl = teeTTL > 0 ? teeTTL : DEFAULT_TEE_TTL;
        config.expiredAt = uint64(block.timestamp) + ttl;
        config.measurementHash = measurements.digest();
        config.teeAttestationOutput = teeOutput;

        emit CVMRefreshed(cvmIdentityHash);
    }

    function rotateCvmIdentityKey(
        bytes32 cvmIdentityHash,
        CVMIdentity calldata newCvmIdentity,
        CVMIdentityCertification calldata newCvmCertification
    ) external override onlyRegistered(cvmIdentityHash) {
        CVMConfig storage config = _configs[cvmIdentityHash];

        if (block.timestamp > config.expiredAt) {
            revert CVM_EXPIRED();
        }

        CertPubkey memory newPubkey = CVMShared.extractPubkeyFromTpmtPublic(newCvmIdentity.tpmtPublic);
        bytes32 newIdentityHash = _computeKeyHash(newPubkey, newCvmIdentity.sigAlgo);

        if (_revokedCvmIdentities[newIdentityHash]) {
            revert CVM_IDENTITY_REVOKED(newIdentityHash);
        }
        if (hasRegistered(newIdentityHash)) {
            revert CVM_ALREADY_REGISTERED(newIdentityHash);
        }

        tpmAttestation.verifyTpmKeyCertification(
            newCvmCertification.certInfo,
            newCvmCertification.akCertificationSig,
            newCvmIdentity.tpmtPublic,
            config.tpmAk,
            ""
        );

        /// @dev for the sole purpose of AK tracking, we do not care about the actual signature algorithm used
        /// @dev the signature algorithm of AK is usually dependent on parameters specified in TPMS_ATTEST structure
        SignatureAlgorithm memory akSigAlgoNull =
            SignatureAlgorithm({scheme: TPMConstants.TPM_ALG_NULL, hashAlgo: TPMConstants.TPM_ALG_NULL});
        bytes32 akHash = _computeKeyHash(config.tpmAk, akSigAlgoNull);
        _akBindings[akHash] = newIdentityHash;

        CVMConfig storage newConfig = _configs[newIdentityHash];
        newConfig.teeType = config.teeType;
        newConfig.cloudType = config.cloudType;
        newConfig.expiredAt = config.expiredAt;
        newConfig.measurementHash = config.measurementHash;
        newConfig.cvmIdentity = newCvmIdentity;
        newConfig.tpmAk = config.tpmAk;
        newConfig.teeAttestationOutput = config.teeAttestationOutput;

        _revokedCvmIdentities[cvmIdentityHash] = true;
        delete _configs[cvmIdentityHash];

        emit CVMIdentityRotated(cvmIdentityHash, newIdentityHash);
    }

    function checkCvmValidity(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (bool)
    {
        return block.timestamp <= _configs[cvmIdentityHash].expiredAt;
    }

    function hasRegistered(bytes32 cvmIdentityHash) public view override returns (bool) {
        return _configs[cvmIdentityHash].cloudType != CloudType.Unset;
    }

    function getMeasurementHash(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (bytes32)
    {
        return _configs[cvmIdentityHash].measurementHash;
    }

    function getCvmIdentity(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (CVMIdentity memory)
    {
        return _configs[cvmIdentityHash].cvmIdentity;
    }

    function getCvmConfig(bytes32 cvmIdentityHash)
        external
        view
        override
        onlyRegistered(cvmIdentityHash)
        returns (CVMConfig memory)
    {
        return _configs[cvmIdentityHash];
    }

    function _computeKeyHash(CertPubkey memory pubkey, SignatureAlgorithm memory sigAlgo)
        private
        pure
        returns (bytes32)
    {
        return CVMShared.computeKeyHash(pubkey, sigAlgo);
    }
}
