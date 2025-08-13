// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    MeasureablePcr,
    Pcr,
    ITpmAttestation
} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {Pubkey, RSALib} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";
import {IDcapAttestation} from "./interfaces/IDcapAttestation.sol";
import {ISnpAttestation, VerifierJournal} from "./interfaces/ISnpAttestation.sol";
import {IWorkloadVerifier, WorkloadCollaterals} from "./interfaces/IWorkloadVerifier.sol";
import {
    TEEVerifiedData,
    ZkProof,
    Bytes64,
    TEEType,
    TeeReportType,
    CloudType,
    LibTEE,
    GoldenMeasurement
} from "./lib/LibTEE.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibString} from "@solady/utils/LibString.sol";

contract WorkloadVerifier is IWorkloadVerifier, UUPSUpgradeable, OwnableUpgradeable {
    using LibString for string;

    IDcapAttestation public override dcapAttestation;
    ISnpAttestation public override snpAttestation;
    ITpmAttestation public override tpmAttestation;
    bool public override allowMockAttestation;

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
        address _tpmAttestationAddr,
        bool _allowMockAttestation
    ) external initializer {
        dcapAttestation = IDcapAttestation(_dcapAttestationAddr);
        snpAttestation = ISnpAttestation(_snpAttestationAddr);
        tpmAttestation = ITpmAttestation(_tpmAttestationAddr);
        allowMockAttestation = _allowMockAttestation;
        __Ownable_init(_initialOwner);
    }

    function verifyAttestation(
        bytes32 _userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _wc
    ) external payable override returns (GoldenMeasurement memory gm) {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert MOCK_ATTESTATION_NOT_ALLOWED();
            return gm;
        }
        gm = _verifyAttestation(_userDataHash, teeType, teeReportType, cloudType, _teeAttestationReport, _wc);
    }

    function verifyAttestationHash(
        bytes32 _userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _wc
    ) external payable override returns (bytes32 gmHash) {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert MOCK_ATTESTATION_NOT_ALLOWED();
            // in mock mode
            // TODO: use preset golden measurement hash
            return gmHash;
        } else {
            GoldenMeasurement memory gm =
                _verifyAttestation(_userDataHash, teeType, teeReportType, cloudType, _teeAttestationReport, _wc);
            gmHash = gm.digest();
        }
    }

    function estimateBaseFeeVerifyOnChain(bytes calldata rawQuote) external payable returns (uint256) {
        uint16 bp = dcapAttestation.getBp();
        uint256 gasBefore = gasleft();
        dcapAttestation.verifyAndAttestOnChain{value: msg.value}(rawQuote);
        uint256 gasAfter = gasleft();
        return (gasBefore - gasAfter) * bp / 10000;
    }

    function _verifyAttestation(
        bytes32 _userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _wc
    ) private returns (GoldenMeasurement memory gm) {
        TEEVerifiedData memory teeVerifiedData =
            _verifyTEE(teeType, teeReportType, cloudType, _teeAttestationReport, _wc);
        _verifyWorkload(_wc, _userDataHash, teeVerifiedData);
        Pcr[] memory pcrs = tpmAttestation.toFinalMeasurement(_wc.pcrs);
        gm = GoldenMeasurement({pcrs: pcrs, tdx: teeVerifiedData.tdx, snp: teeVerifiedData.snp});
    }

    function _verifyTEE(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _report,
        WorkloadCollaterals calldata _wc
    ) private returns (TEEVerifiedData memory) {
        TEEVerifiedData memory teeVerifiedData;
        if (teeType == TEEType.IntelTDX) {
            teeVerifiedData = _verifyTdxAttestation(teeReportType, _report);
        } else if (teeType == TEEType.AmdSevSnp) {
            teeVerifiedData = _verifySnpAttestation(teeReportType, _report);
        } else {
            revert INVALID_TEE_TYPE(teeType);
        }
        if (cloudType == CloudType.Azure) {
            bytes32 localReportData = sha256(_wc.akPub);
            if (teeVerifiedData.userReportData.first != localReportData) {
                revert TEE_REPORT_DATA_MISMATCH(teeVerifiedData.userReportData.first, localReportData);
            }
            teeVerifiedData.akPub = _varDataPubkey(string(_wc.akPub));
        }
        return teeVerifiedData;
    }

    function _verifySnpAttestation(TeeReportType _reportType, bytes calldata _report)
        private
        returns (TEEVerifiedData memory teeVerifiedData)
    {
        ISnpAttestation.ZkCoProcessorType zkType;
        if (_reportType == TeeReportType.ZkSuccinct) {
            zkType = ISnpAttestation.ZkCoProcessorType.Succinct;
        } else if (_reportType == TeeReportType.ZkRiscZero) {
            zkType = ISnpAttestation.ZkCoProcessorType.RiscZero;
        } else {
            revert INVALID_TEE_REPORT_TYPE(_reportType);
        }

        ZkProof memory zkProof = abi.decode(_report, (ZkProof));
        VerifierJournal memory output =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
        return LibTEE.snpOutput(output.rawReport);
    }

    function _verifyTdxAttestation(TeeReportType _reportType, bytes calldata _report)
        private
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
                revert INVALID_TEE_REPORT_TYPE(_reportType);
            }
            (succ, output) = dcapAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
        }
        if (!succ) {
            revert FAILED_TO_VERIFY_TEE();
        }

        // offset 11 + SGX_REPORT_SIZE (384 bytes)
        if (output.length < 395) {
            revert INVALID_TEE_REPORT();
        }

        return LibTEE.tdxOutput(output);
    }

    function _verifyWorkload(
        WorkloadCollaterals calldata _wc,
        bytes32 _userDataHash,
        TEEVerifiedData memory _teeVerifiedData
    ) private {
        // Step 1: Verify TPM quote
        bool success;
        string memory errorMessage;
        if (_teeVerifiedData.akPub.empty()) {
            (success, errorMessage) = tpmAttestation.verifyTpmQuote(_wc.tpmQuote, _wc.tpmSignature, _wc.certs);
        } else {
            (success, errorMessage) =
                tpmAttestation.verifyTpmQuote(_wc.tpmQuote, _wc.tpmSignature, _teeVerifiedData.akPub);
        }
        if (!success) {
            revert FAILED_TO_VERIFY_TPM_QUOTE(errorMessage);
        }

        // Step 2: Check PCR measurements and extract extraData from the quote
        bytes memory extraData;
        (success, extraData) = tpmAttestation.checkPcrMeasurements(_wc.tpmQuote, _wc.pcrs);
        if (!success) {
            revert FAILED_TO_CHECK_PCR_MEASUREMENTS(string(extraData));
        }

        // Step 3: Compare userDataHash with extraData
        bytes32 data = bytes32(extraData);
        if (data != _userDataHash) {
            revert TPM_DATA_MISMATCH(data, _userDataHash);
        }

        LibTEE.verifyReportID(_wc, _teeVerifiedData);
    }

    function _varDataPubkey(string memory data) private pure returns (Pubkey memory) {
        uint256 off = 0;
        uint256 pos;
        pos = data.indexOf("\"kid\":\"HCLAkPub\"", off);
        if (pos == type(uint256).max) {
            revert("not found");
        }
        off = pos + 16;

        string memory kty;
        {
            pos = data.indexOf("\"kty\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid kty");
            }
            off = pos + 7;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid kty");
            }
            kty = data.slice(off, pos);
            require(kty.eq("RSA"), "invalid kty");
            off = pos + 1;
        }

        // e
        string memory eBase64;
        {
            pos = data.indexOf("\"e\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid e");
            }
            off = pos + 5;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid e");
            }
            eBase64 = data.slice(off, pos);
            off = pos + 1;
        }

        // n
        string memory nBase64;
        {
            pos = data.indexOf("\"n\":\"", off);
            if (pos == type(uint256).max) {
                revert("invalid n");
            }
            off = pos + 5;

            pos = data.indexOf("\"", off);
            if (pos == type(uint256).max) {
                revert("invalid n");
            }
            nBase64 = data.slice(off, pos);
            off = pos + 1;
        }

        pos = data.indexOf("\"kid\":\"HCLEkPub\"", off);
        if (pos == type(uint256).max) {
            revert("data mixed up");
        }

        return RSALib.newRsaPubkey(Base64.decode(eBase64), Base64.decode(nBase64));
    }
}
