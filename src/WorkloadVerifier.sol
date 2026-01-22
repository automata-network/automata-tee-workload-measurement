// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    MeasureablePcr,
    Pcr,
    ITpmAttestation
} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {IDcapAttestation} from "./interfaces/IDcapAttestation.sol";
import {
    ISnpAttestation,
    VerifierJournal as SnpVerifierJournal,
    VerificationResult as SnpVerificationResult
} from "./interfaces/ISnpAttestation.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal as NitroVerifierJournal,
    VerificationResult as NitroVerificationResult
} from "./interfaces/INitroEnclaveVerifier.sol";
import {IWorkloadVerifier, WorkloadCollaterals} from "./interfaces/IWorkloadVerifier.sol";
import {
    TEEVerifiedData,
    ZkProof,
    Bytes48,
    TEEType,
    TeeReportType,
    CloudType,
    LibTEE,
    Measurement
} from "./lib/LibTEE.sol";
import {Base64} from "@solady/utils/Base64.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {ZeroAddress} from "@automata-network/automata-tpm-attestation/types/Errors.sol";

/// @title WorkloadVerifier
/// @notice Verifies TEE attestations and TPM quotes for workload integrity
/// @dev This contract acts as the main entry point for TEE attestation verification, supporting
///      both Intel TDX and AMD SEV-SNP attestation types. It orchestrates the verification process by:
///      1. Verifying TEE attestation reports (via DCAP for TDX or SNP attestation for SEV-SNP)
///      2. Verifying TPM quotes and their certificate chains
///      3. Checking PCR measurements against expected values
///      4. Binding TEE report data to TPM attestation keys
///      The contract supports multiple cloud providers (Azure, GCP) with different attestation flows:
///      - Azure: TPM AK public key is embedded in TEE report data as a hash
///      - GCP: TPM AK public key is derived from certificate chain
///
/// @custom:security-contact security@ata.network
///
/// @custom:security This contract is upgradeable. Only the owner can authorize upgrades.
contract WorkloadVerifier is IWorkloadVerifier, UUPSUpgradeable, OwnableUpgradeable {
    using LibString for string;

    IDcapAttestation public override dcapAttestation;
    ISnpAttestation public override snpAttestation;
    ITpmAttestation public override tpmAttestation;
    INitroEnclaveVerifier public override nitroAttestation;

    uint256[46] private __gap;

    constructor() {
        _disableInitializers();
    }

    /// @notice Only the owner can authorize an upgrade.
    /// @param newImplementation The address of the new implementation.
    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
    }

    /// @notice Initializes the WorkloadVerifier contract with required dependencies
    /// @dev Can only be called once due to initializer modifier. Sets up all attestation verifier addresses.
    /// @param initialOwner The address that will own this contract and can authorize upgrades
    /// @param dcapAttestationAddr Address of the DCAP attestation verifier for Intel TDX
    /// @param snpAttestationAddr Address of the SNP attestation verifier for AMD SEV-SNP
    /// @param tpmAttestationAddr Address of the TPM attestation verifier for quote verification
    function initialize(
        address initialOwner,
        address dcapAttestationAddr,
        address snpAttestationAddr,
        address tpmAttestationAddr
    ) external initializer {
        if (dcapAttestationAddr == address(0)) revert ZeroAddress("dcapAttestation");
        if (snpAttestationAddr == address(0)) revert ZeroAddress("snpAttestation");
        if (tpmAttestationAddr == address(0)) revert ZeroAddress("tpmAttestation");

        dcapAttestation = IDcapAttestation(dcapAttestationAddr);
        snpAttestation = ISnpAttestation(snpAttestationAddr);
        tpmAttestation = ITpmAttestation(tpmAttestationAddr);
        _transferOwnership(initialOwner);
    }

    /// @notice Updates the attestation verifier contract addresses
    /// @dev Can only be called by the owner. Allows updating verifier contracts without redeployment.
    /// @param dcapAttestationAddr New address of the DCAP attestation verifier for Intel TDX
    /// @param snpAttestationAddr New address of the SNP attestation verifier for AMD SEV-SNP
    /// @param tpmAttestationAddr New address of the TPM attestation verifier for quote verification
    function updateDependencies(address dcapAttestationAddr, address snpAttestationAddr, address tpmAttestationAddr)
        external
        onlyOwner
    {
        if (dcapAttestationAddr == address(0)) revert ZeroAddress("dcapAttestation");
        if (snpAttestationAddr == address(0)) revert ZeroAddress("snpAttestation");
        if (tpmAttestationAddr == address(0)) revert ZeroAddress("tpmAttestation");

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
        returns (bytes memory teeOutput, TEEVerifiedData memory teeVerifiedData, Measurement memory measurement)
    {
        (teeOutput, teeVerifiedData, measurement) =
            _verifyAttestation(teeType, teeReportType, cloudType, teeAttestationReport, wc);
    }

    /// @notice Compute the keccak256 hash of a Measurement struct
    /// @param m The measurement to hash
    /// @return The keccak256 hash of the encoded measurement
    function computeMeasurementHash(Measurement memory m) external pure override returns (bytes32) {
        return m.digest();
    }

    function _getMeasurement(TEEVerifiedData memory teeVerifiedData, MeasureablePcr[] calldata measuredPcrs)
        private
        view
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
        } else if (teeType == TEEType.Nitro) {
            teeVerifiedData = LibTEE.nitroOutput(teeOutput);
        } else {
            revert INVALID_TEE_TYPE(teeType);
        }
    }

    function parseVarKeyJson(string calldata varKey) external pure override returns (CertPubkey memory) {
        return _varDataPubkey(varKey);
    }

    function _verifyAttestation(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) private returns (bytes memory, TEEVerifiedData memory, Measurement memory) {
        bytes memory teeOutput = _verifyTEE(teeType, teeReportType, teeAttestationReport);

        // Step 0: pre-process teeOutput to get TEE Verified Data
        TEEVerifiedData memory teeVerifiedData;
        {
            teeVerifiedData = parseTeeOutput(teeType, teeOutput);
            if (cloudType == CloudType.Azure) {
                bytes32 localReportData = sha256(wc.akPub);
                require(
                    teeVerifiedData.userReportData.first == localReportData,
                    TEE_REPORT_DATA_MISMATCH(teeVerifiedData.userReportData.first, localReportData)
                );
                teeVerifiedData.akPub = _varDataPubkey(string(wc.akPub));
            }
        }

        // Step 1: Verify workload and get final measurement
        Measurement memory measurement;
        if (teeType == TEEType.Nitro) {
            // Nitro attestations contain PCR measurements directly - skip TPM verification
            measurement.pcrs = LibTEE._getFinalMeasurementFromNitro(teeVerifiedData.nitro.pcrs);
        } else {
            measurement = _verifyWorkload(cloudType, wc, teeVerifiedData);
        }

        return (teeOutput, teeVerifiedData, measurement);
    }

    function _verifyTEE(TEEType teeType, TeeReportType teeReportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        if (teeType == TEEType.IntelTDX) {
            teeOutput = _verifyTdxAttestation(teeReportType, report);
        } else if (teeType == TEEType.AmdSevSnp) {
            teeOutput = _verifySnpAttestation(teeReportType, report);
        } else if (teeType == TEEType.Nitro) {
            teeOutput = _verifyNitroAttestation(teeReportType, report);
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
        SnpVerifierJournal memory output =
            snpAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);

        require(uint8(output.result) == uint8(SnpVerificationResult.Success), FAILED_TO_VERIFY_TEE());

        teeOutput = output.rawReport;
    }

    function _verifyTdxAttestation(TeeReportType reportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        IDcapAttestation cachedDcapAttestation = dcapAttestation;

        if (reportType == TeeReportType.Unset) {
            revert INVALID_TEE_REPORT_TYPE(reportType);
        } else if (reportType == TeeReportType.Solidity) {
            bool succ;
            (succ, teeOutput) = cachedDcapAttestation.verifyAndAttestOnChain{value: msg.value}(report);
            require(succ, FAILED_TO_VERIFY_TEE());
            require(teeOutput.length >= 395, INVALID_TEE_REPORT());
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
            (succ, teeOutput) =
                cachedDcapAttestation.verifyAndAttestWithZKProof(zkProof.output, zkType, zkProof.proofBytes);
            require(succ, FAILED_TO_VERIFY_TEE());
            require(teeOutput.length >= 395, INVALID_TEE_REPORT());
        }
    }

    function _verifyNitroAttestation(TeeReportType reportType, bytes calldata report)
        private
        returns (bytes memory teeOutput)
    {
        INitroEnclaveVerifier.ZkCoProcessorType zkType;
        if (reportType == TeeReportType.ZkSuccinct) {
            zkType = INitroEnclaveVerifier.ZkCoProcessorType.Succinct;
        } else if (reportType == TeeReportType.ZkRiscZero) {
            zkType = INitroEnclaveVerifier.ZkCoProcessorType.RiscZero;
        } else {
            revert INVALID_TEE_REPORT_TYPE(reportType);
        }

        ZkProof memory zkProof = abi.decode(report, (ZkProof));
        NitroVerifierJournal memory output = nitroAttestation.verify(zkProof.output, zkType, zkProof.proofBytes);

        require(uint8(output.result) == uint8(NitroVerificationResult.Success), FAILED_TO_VERIFY_TEE());

        teeOutput = abi.encode(bytes(output.moduleId), abi.encode(output.pcrs), output.userData);
    }

    function _verifyWorkload(
        CloudType cloudType,
        WorkloadCollaterals calldata wc,
        TEEVerifiedData memory teeVerifiedData
    ) private returns (Measurement memory measurement) {
        // Cache tpmAttestation to memory to save on multiple SLOADs
        ITpmAttestation cachedTpmAttestation = tpmAttestation;

        // Step 1: Verify TPM quote
        {
            bool success;
            string memory errorMessage;

            if (teeVerifiedData.akPub.empty()) {
                // Defensive check: prevent excessive memory allocation before verifyCertChain
                // CertChainRegistry already enforces max length of 4, but reject early for robustness
                require(wc.certs.length > 0 && wc.certs.length <= 4, "Invalid certificate chain length");
                bytes memory ret;
                (success, ret) = cachedTpmAttestation.verifyTpmQuote(wc.tpmQuote, wc.tpmSignature, wc.certs);
                if (success) {
                    teeVerifiedData.akPub = abi.decode(ret, (CertPubkey));
                }
            } else {
                (success, errorMessage) = cachedTpmAttestation.verifyTpmQuoteWithTrustedAkPub(
                    wc.tpmQuote, wc.tpmSignature, teeVerifiedData.akPub
                );
            }

            require(success, FAILED_TO_VERIFY_TPM_QUOTE(errorMessage));
        }

        // Step 2: Check PCR measurements against the TPM quote
        {
            (bool success, bytes memory data) = cachedTpmAttestation.checkPcrMeasurements(wc.tpmQuote, wc.pcrs);
            require(success, FAILED_TO_CHECK_PCR_MEASUREMENTS(string(data)));
        }

        // Step 3: Verify report ID with MeasureablePcr
        LibTEE.verifyReportID(cloudType, wc.reportId, wc.pcrs, 15, teeVerifiedData);

        // Step 4: Convert to final measurement
        measurement = _getMeasurement(teeVerifiedData, wc.pcrs);
    }

    /// @notice Extracts the attestation key (AK) public key from Azure TPM JSON data
    /// @dev This parser implements a STRICT substring matching algorithm (lower gas cost) for Azure
    ///      TPM attestation keys. It is NOT compliant with RFC7517 (JSON Web Key).
    ///      Example JSON structure:
    ///      {"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"...","n":"..."},...]}
    /// @param data The JSON string containing the TPM attestation key
    /// @return CertPubkey The extracted RSA public key
    function _varDataPubkey(string memory data) private pure returns (CertPubkey memory) {
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

        return LibX509.newRsaPubkey(Base64.decode(nBase64), Base64.decode(eBase64));
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
