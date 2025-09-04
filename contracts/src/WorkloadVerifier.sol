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
import {ISnpAttestation, VerifierJournal, VerificationResult} from "./interfaces/ISnpAttestation.sol";
import {IWorkloadVerifier, WorkloadCollaterals} from "./interfaces/IWorkloadVerifier.sol";
import {
    TEEVerifiedData,
    ZkProof,
    Bytes48,
    TEEType,
    TeeReportType,
    CloudType,
    LibTEE,
    Measurement,
    TdxMeasurement,
    SnpMeasurement
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
        address initialOwner,
        address dcapAttestationAddr,
        address snpAttestationAddr,
        address tpmAttestationAddr,
        bool mockAllowed
    ) external initializer {
        dcapAttestation = IDcapAttestation(dcapAttestationAddr);
        snpAttestation = ISnpAttestation(snpAttestationAddr);
        tpmAttestation = ITpmAttestation(tpmAttestationAddr);
        allowMockAttestation = mockAllowed;
        __Ownable_init(initialOwner);
    }

    function updateDependencies(address dcapAttestationAddr, address snpAttestationAddr, address tpmAttestationAddr)
        external
        onlyOwner
    {
        dcapAttestation = IDcapAttestation(dcapAttestationAddr);
        snpAttestation = ISnpAttestation(snpAttestationAddr);
        tpmAttestation = ITpmAttestation(tpmAttestationAddr);
    }

    function verifyAttestation(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    )
        external
        payable
        override
        returns (bytes memory teeOutput, TEEVerifiedData memory teeVerifiedData, bytes memory tpmExtraData)
    {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert MOCK_ATTESTATION_NOT_ALLOWED();
            return (teeOutput, teeVerifiedData, tpmExtraData);
        }
        (teeOutput, teeVerifiedData, tpmExtraData) =
            _verifyAttestation(teeType, teeReportType, cloudType, teeAttestationReport, wc);
    }

    function verifyAttestationAndGetMeasurement(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external payable override returns (bytes memory teeOutput, Measurement memory m, bytes memory tpmExtraData) {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert MOCK_ATTESTATION_NOT_ALLOWED();
            return (teeOutput, m, tpmExtraData);
        }

        TEEVerifiedData memory teeVerifiedData;
        (teeOutput, teeVerifiedData, tpmExtraData) =
            _verifyAttestation(teeType, teeReportType, cloudType, teeAttestationReport, wc);
        m = getMeasurement(teeVerifiedData, wc.pcrs);
    }

    function verifyAttestationAndGetMeasurementHash(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external payable override returns (bytes memory teeOutput, bytes32 measurementHash, bytes memory tpmExtraData) {
        if (teeType == TEEType.Mock) {
            if (!allowMockAttestation) revert MOCK_ATTESTATION_NOT_ALLOWED();
            // in mock mode
            // TODO: use preset golden measurement hash
            return (teeOutput, measurementHash, tpmExtraData);
        } else {
            TEEVerifiedData memory teeVerifiedData;
            (teeOutput, teeVerifiedData, tpmExtraData) =
                _verifyAttestation(teeType, teeReportType, cloudType, teeAttestationReport, wc);
            Measurement memory m = getMeasurement(teeVerifiedData, wc.pcrs);
            measurementHash = m.digest();
        }
    }

    function estimateBaseFeeVerifyOnChain(bytes calldata rawQuote) external payable returns (uint256) {
        uint16 bp = dcapAttestation.getBp();
        uint256 gasBefore = gasleft();
        dcapAttestation.verifyAndAttestOnChain{value: msg.value}(rawQuote);
        uint256 gasAfter = gasleft();
        return (gasBefore - gasAfter) * bp / 10000;
    }

    function getMeasurement(TEEVerifiedData memory teeVerifiedData, MeasureablePcr[] memory measuredPcrs)
        public
        view
        override
        returns (Measurement memory m)
    {
        Pcr[] memory pcrs = tpmAttestation.toFinalMeasurement(measuredPcrs);

        // exclude TDX rtmr3 values from measurement bc it contains the UUID of the attestation
        // which gets reset when the VM reboots
        if (!teeVerifiedData.tdx.rtmr3.isZero()) {
            teeVerifiedData.tdx.rtmr3 = Bytes48({first: bytes32(0), second: bytes16(0)});
        }

        m = Measurement({pcrs: pcrs, tdx: teeVerifiedData.tdx, snp: teeVerifiedData.snp});
    }

    function parseTeeOutput(TEEType teeType, bytes memory teeOutput)
        public
        pure
        override
        returns (TEEVerifiedData memory teeVerifiedData)
    {
        if (teeType == TEEType.IntelTDX) {
            teeVerifiedData = LibTEE.tdxOutput(teeOutput);
        } else if (teeType == TEEType.AmdSevSnp) {
            teeVerifiedData = LibTEE.snpOutput(teeOutput);
        }
    }

    function parseVarKeyJson(string calldata varKey) external pure override returns (Pubkey memory akPub) {
        return _varDataPubkey(varKey);
    }

    function _verifyAttestation(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) private returns (bytes memory, TEEVerifiedData memory, bytes memory) {
        bytes memory teeOutput = _verifyTEE(teeType, teeReportType, teeAttestationReport);

        // Step 0: pre-process teeOutput to get TEE Verified Data
        TEEVerifiedData memory teeVerifiedData;
        {
            teeVerifiedData = parseTeeOutput(teeType, teeOutput);
            if (cloudType == CloudType.Azure) {
                bytes32 localReportData = sha256(wc.akPub);
                if (teeVerifiedData.userReportData.first != localReportData) {
                    revert TEE_REPORT_DATA_MISMATCH(teeVerifiedData.userReportData.first, localReportData);
                }
                teeVerifiedData.akPub = _varDataPubkey(string(wc.akPub));
            }
        }

        bytes memory tpmExtraData = _verifyWorkload(cloudType, wc, teeVerifiedData);
        return (teeOutput, teeVerifiedData, tpmExtraData);
    }

    function _verifyTEE(TEEType teeType, TeeReportType teeReportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        if (teeType == TEEType.IntelTDX) {
            teeOutput = _verifyTdxAttestation(teeReportType, report);
        } else if (teeType == TEEType.AmdSevSnp) {
            teeOutput = _verifySnpAttestation(teeReportType, report);
        } else {
            revert INVALID_TEE_TYPE(teeType);
        }
    }

    function _verifySnpAttestation(TeeReportType reportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        ISnpAttestation.ZkCoProcessorType zkType;
        if (reportType == TeeReportType.ZkSuccinct) {
            zkType = ISnpAttestation.ZkCoProcessorType.Succinct;
        } else if (reportType == TeeReportType.ZkRiscZero) {
            zkType = ISnpAttestation.ZkCoProcessorType.RiscZero;
        } else {
            revert INVALID_TEE_REPORT_TYPE(reportType);
        }

        ZkProof memory zkProof = abi.decode(report, (ZkProof));
        VerifierJournal memory output =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);

        if (uint8(output.result) != uint8(VerificationResult.Success)) {
            revert FAILED_TO_VERIFY_TEE();
        }

        teeOutput = output.rawReport;
    }

    function _verifyTdxAttestation(TeeReportType reportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        if (reportType == TeeReportType.Solidity) {
            bool succ;
            (succ, teeOutput) = dcapAttestation.verifyAndAttestOnChain{value: msg.value}(report);
            if (!succ) {
                revert FAILED_TO_VERIFY_TEE();
            }
            if (teeOutput.length < 395) {
                revert INVALID_TEE_REPORT();
            }
        } else {
            ZkProof memory zkProof = abi.decode(report, (ZkProof));
            IDcapAttestation.ZkCoProcessorType zkType;
            if (reportType == TeeReportType.ZkSuccinct) {
                zkType = IDcapAttestation.ZkCoProcessorType.Succinct;
            } else if (reportType == TeeReportType.ZkRiscZero) {
                zkType = IDcapAttestation.ZkCoProcessorType.RiscZero;
            } else {
                revert INVALID_TEE_REPORT_TYPE(reportType);
            }
            bool succ;
            (succ, teeOutput) = dcapAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
            if (!succ) {
                revert FAILED_TO_VERIFY_TEE();
            }
            if (teeOutput.length < 395) {
                revert INVALID_TEE_REPORT();
            }
        }
    }

    function _verifyWorkload(
        CloudType cloudType,
        WorkloadCollaterals calldata wc,
        TEEVerifiedData memory teeVerifiedData
    ) private returns (bytes memory extraData) {
        // Step 1: Verify TPM quote
        {
            if (cloudType == CloudType.Azure) {
                bytes32 localReportData = sha256(wc.akPub);
                if (teeVerifiedData.userReportData.first != localReportData) {
                    revert TEE_REPORT_DATA_MISMATCH(teeVerifiedData.userReportData.first, localReportData);
                }
                teeVerifiedData.akPub = _varDataPubkey(string(wc.akPub));
            }
            bool success;
            string memory errorMessage;

            if (teeVerifiedData.akPub.empty()) {
                bytes memory ret;
                (success, ret) = tpmAttestation.verifyTpmQuote(wc.tpmQuote, wc.tpmSignature, wc.certs);
                if (success) {
                    teeVerifiedData.akPub = abi.decode(ret, (Pubkey));
                }
            } else {
                (success, errorMessage) =
                    tpmAttestation.verifyTpmQuote(wc.tpmQuote, wc.tpmSignature, teeVerifiedData.akPub);
            }

            if (!success) {
                revert FAILED_TO_VERIFY_TPM_QUOTE(errorMessage);
            }
        }

        // Step 2: Check PCR measurements and extract extraData from the quote
        {
            (bool success, bytes memory data) = tpmAttestation.checkPcrMeasurements(wc.tpmQuote, wc.pcrs);
            if (!success) {
                revert FAILED_TO_CHECK_PCR_MEASUREMENTS(string(data));
            }
            extraData = data;
        }

        LibTEE.verifyReportID(wc, teeVerifiedData);
    }

    function _varDataPubkey(string memory data) private pure returns (Pubkey memory) {
        uint256 off = 0;
        uint256 pos;
        pos = data.indexOf("\"kid\":\"HCLAkPub\"", off);
        if (pos == type(uint256).max) {
            revert("not found");
        }
        off = pos + 16;

        off = _verifyAndGetOffsetForKty(data, off);

        string memory eBase64;
        (eBase64, off) = _extractE(data, off);

        string memory nBase64;
        (nBase64, off) = _extractN(data, off);

        pos = data.indexOf("\"kid\":\"HCLEkPub\"", off);
        if (pos == type(uint256).max) {
            revert("data mixed up");
        }

        return RSALib.newRsaPubkey(Base64.decode(eBase64), Base64.decode(nBase64));
    }

    function _verifyAndGetOffsetForKty(string memory data, uint256 off) private pure returns (uint256) {
        uint256 pos = data.indexOf("\"kty\":\"", off);
        if (pos == type(uint256).max) {
            revert("invalid kty");
        }
        off = pos + 7;

        pos = data.indexOf("\"", off);
        if (pos == type(uint256).max) {
            revert("invalid kty");
        }
        string memory kty = data.slice(off, pos);
        require(kty.eq("RSA"), "invalid kty");
        return pos + 1;
    }

    function _extractE(string memory data, uint256 off) private pure returns (string memory, uint256) {
        uint256 pos = data.indexOf("\"e\":\"", off);
        if (pos == type(uint256).max) {
            revert("invalid e");
        }
        off = pos + 5;

        pos = data.indexOf("\"", off);
        if (pos == type(uint256).max) {
            revert("invalid e");
        }
        return (data.slice(off, pos), pos + 1);
    }

    function _extractN(string memory data, uint256 off) private pure returns (string memory, uint256) {
        uint256 pos = data.indexOf("\"n\":\"", off);
        if (pos == type(uint256).max) {
            revert("invalid n");
        }
        off = pos + 5;

        pos = data.indexOf("\"", off);
        if (pos == type(uint256).max) {
            revert("invalid n");
        }
        return (data.slice(off, pos), pos + 1);
    }
}
