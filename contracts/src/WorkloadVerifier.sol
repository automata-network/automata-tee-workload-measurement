// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IDcapAttestation} from "./interfaces/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal} from "./interfaces/ISnpAttestation.sol";
import {IAttestationVerifier} from "./interfaces/IAttestationVerifier.sol";
import {ICertChainRegistry} from "./interfaces/ICertChainRegistry.sol";
import {WorkloadCollaterals, MeasureablePcr, LibTPM} from "./lib/LibTPM.sol";
import {TEEVerifiedData, ZkProof, Bytes64, TEEType, TeeReportType, CloudType, LibTEE} from "./lib/LibTEE.sol";
import {CertPubkey} from "./lib/LibX509.sol";

contract WorkloadVerifier is UUPSUpgradeable, OwnableUpgradeable {
    IDcapAttestation public dcapAttestation;
    ISnpAttestation public snpAttestation;
    bool public allowMockAttestation;
    address public certChainRegistryAddr;

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

    function initialize(
        address _initialOwner,
        address _dcapAttestationAddr,
        address _snpAttestationAddr,
        address _certChainRegistryAddr,
        bool _allowMockAttestation
    ) public initializer {
        dcapAttestation = IDcapAttestation(_dcapAttestationAddr);
        snpAttestation = ISnpAttestation(_snpAttestationAddr);
        allowMockAttestation = _allowMockAttestation;
        certChainRegistryAddr = _certChainRegistryAddr;
        _transferOwnership(_initialOwner);
    }

    function verifyAttestation(
        bytes32 _userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _wc
    ) external payable returns (bytes32) {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert IAttestationVerifier.MOCK_ATTESTATION_NOT_ALLOWED();
            // in mock mode
            // TODO: use preset golden measurement hash
            return bytes32(0);
        }

        TEEVerifiedData memory teeVerifiedData =
            verifyTEE(teeType, teeReportType, cloudType, _teeAttestationReport, _wc);
        verifyWorkload(_wc, _userDataHash, teeVerifiedData);
        return LibTEE.goldenMeasurement(_wc.pcrs, teeVerifiedData.tdx, teeVerifiedData.snp).digest();
    }

    function verifyTEE(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _report,
        WorkloadCollaterals calldata _wc
    ) internal returns (TEEVerifiedData memory) {
        TEEVerifiedData memory teeVerifiedData;
        if (teeType == TEEType.IntelTDX) {
            teeVerifiedData = verifyTdxAttestation(teeReportType, _report);
        } else if (teeType == TEEType.AmdSevSnp) {
            teeVerifiedData = verifySnpAttestation(teeReportType, _report);
        } else {
            revert IAttestationVerifier.INVALID_TEE_TYPE(teeType);
        }
        if (cloudType == CloudType.Azure) {
            bytes32 localReportData = sha256(_wc.akPub);
            if (teeVerifiedData.userReportData.first != localReportData) {
                revert IAttestationVerifier.REPORT_DATA_MISMATCH(teeVerifiedData.userReportData.first, localReportData);
            }
            teeVerifiedData.akPub = LibTPM.varDataPubkey(string(_wc.akPub));
        }
        return teeVerifiedData;
    }

    function verifySnpAttestation(TeeReportType _reportType, bytes calldata _report)
        internal
        returns (TEEVerifiedData memory teeVerifiedData)
    {
        ISnpAttestation.ZkCoProcessorType zkType;
        if (_reportType == TeeReportType.ZkSuccinct) {
            zkType = ISnpAttestation.ZkCoProcessorType.Succinct;
        } else if (_reportType == TeeReportType.ZkRiscZero) {
            zkType = ISnpAttestation.ZkCoProcessorType.RiscZero;
        } else {
            revert IAttestationVerifier.INVALID_TEE_REPORT_TYPE(_reportType);
        }

        ZkProof memory zkProof = abi.decode(_report, (ZkProof));
        VerifierJournal memory output =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
        return LibTEE.snpOutput(output.rawReport);
    }

    function verifyTdxAttestation(TeeReportType _reportType, bytes calldata _report)
        internal
        returns (TEEVerifiedData memory)
    {
        bool succ;
        bytes memory output;

        if (_reportType == TeeReportType.Solidity) {
            (succ, output) = dcapAttestation.verifyAndAttestOnChain{value: msg.value}(_report);
        } else {
            ZkProof memory zkProof = abi.decode(_report, (ZkProof));
            IDcapAttestation.ZkCoProcessorType zkType;
            if (_reportType == TeeReportType.ZkSuccinct) {
                zkType = IDcapAttestation.ZkCoProcessorType.Succinct;
            } else if (_reportType == TeeReportType.ZkRiscZero) {
                zkType = IDcapAttestation.ZkCoProcessorType.RiscZero;
            } else {
                revert IAttestationVerifier.INVALID_TEE_REPORT_TYPE(_reportType);
            }
            (succ, output) = dcapAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
        }
        if (!succ) {
            revert IAttestationVerifier.INVALID_REPORT();
        }

        if (output.length < 64) {
            revert IAttestationVerifier.INVALID_REPORT_DATA();
        }

        return LibTEE.tdxOutput(output);
    }

    function verifyWorkload(
        WorkloadCollaterals calldata _wc,
        bytes32 _userDataHash,
        TEEVerifiedData memory _teeVerifiedData
    ) public {
        if (_teeVerifiedData.akPub.empty()) {
            _teeVerifiedData.akPub = LibTPM.verifyAkPub(_wc.certs, certChainRegistryAddr);
        }

        _wc.verifyTpmQuote(_teeVerifiedData.akPub, certChainRegistryAddr);

        bytes32 extraDataHash = LibTPM.quoteExtraData(_wc.tpmQuote);
        require(extraDataHash == _userDataHash, "user report data mismatch");

        LibTPM.verifyPcrs(_wc.pcrs, _wc.tpmQuote);
        LibTEE.verifyReportID(_wc, _teeVerifiedData);
    }

    /**
     * @dev Estimates the fee for verifying the quote on-chain.
     * @param rawQuote The raw quote data.
     * @return The estimated fee.
     * @notice The actual fee is determined by multiplying the base fee with the gas price.
     */
    function estimateBaseFeeVerifyOnChain(bytes calldata rawQuote) external payable returns (uint256) {
        uint16 bp = dcapAttestation.getBp();
        uint256 gasBefore = gasleft();
        dcapAttestation.verifyAndAttestOnChain{value: msg.value}(rawQuote);
        uint256 gasAfter = gasleft();
        return (gasBefore - gasAfter) * bp / 10000;
    }
}
