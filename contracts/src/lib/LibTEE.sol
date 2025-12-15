// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import { Pcr } from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import { WorkloadCollaterals } from "../interfaces/IWorkloadVerifier.sol";
import { Bytes48, Bytes64, LibBytes } from "@automata-network/automata-tpm-attestation/lib/LibBytes.sol";
import { Sha2Ext } from "./Sha2Ext.sol";

using LibBytes for bytes;
using LibBytes for bytes32;
using LibTEE for Measurement global;
using LibTEE for TEEType global;
using LibTEE for CloudType global;
using LibTEE for TdxMeasurement global;
using LibTEE for SnpMeasurement global;

enum TEEType {
    Unknown,
    IntelTDX,
    AmdSevSnp
}

enum TeeReportType {
    Unset,
    Solidity,
    ZkSuccinct,
    ZkRiscZero
}

enum CloudType {
    Unset,
    GCP,
    Azure
}

struct ZkProof {
    bytes output;
    bytes proofBytes;
}

struct Measurement {
    Pcr[] pcrs;
    TdxMeasurement tdx;
    SnpMeasurement snp;
}

struct TEEVerifiedData {
    // TEE Report Data
    Bytes64 userReportData;
    // VM Instance-level unique ID
    // TDX: UUID
    // SNP: sev-snp.report_id
    bytes32 reportID;
    CertPubkey akPub; // verified akPub
    TdxMeasurement tdx;
    SnpMeasurement snp;
}

struct SnpMeasurement {
    Bytes48 measurement;
}

struct TdxMeasurement {
    Bytes48 mrtd;
    Bytes48 mrseam;
    Bytes48 rtmr0;
    Bytes48 rtmr1;
    Bytes48 rtmr2;
    Bytes48 rtmr3;
}

error InvalidReportID();
error UnexpectedSGXReport();

/// @custom:security-contact security@ata.network
library LibTEE {
    /// @notice Verifies the TEE report ID against TPM PCR measurements
    /// @dev This function validates that the workload report ID matches the TEE attestation data
    ///      by checking a specific TPM Platform Configuration Register (PCR), which stores
    ///      the extended hash of the report ID.
    /// @dev Verification Logic by TEE Type and Cloud Provider:
    ///      (Examples below use typical PCR indices: 15 or 16)
    ///      GCP + Intel TDX:
    ///      - teeData.reportID = 0 (not populated in TDX report)
    ///      - wc.reportId = UUID from workload
    ///      - PCR[pcrIndex] = SHA256_extend(0, SHA256(uuid))
    ///      - RTMR3 = SHA384_extend(0, SHA384(uuid))
    ///      - Verification: Check both PCR[pcrIndex] and RTMR3 match expected values
    ///      GCP + AMD SEV-SNP:
    ///      - teeData.reportID = SNP report's report_id field
    ///      - wc.reportId = SNP report_id (should match teeData.reportID)
    ///      - PCR[pcrIndex] = SHA256_extend(0, reportID)
    ///      - Verification: Check PCR[pcrIndex] matches and wc.reportId equals teeData.reportID
    ///      Azure + Intel TDX:
    ///      - teeData.reportID = 0
    ///      - wc.reportId = bytes16(0) (empty)
    ///      - PCR[pcrIndex] = SHA256_extend(0, 0)
    ///      - RTMR3 = 0
    ///      - Verification: If PCR[pcrIndex] is zero, verification passes (no UUID tracking)
    ///      Azure + AMD SEV-SNP:
    ///      - teeData.reportID = SNP report's report_id
    ///      - PCR[pcrIndex] may be zero (binding disabled, akPub provides binding instead)
    ///      - Verification: If cloudType is Azure and PCR[pcrIndex] is zero, skip check;
    ///        otherwise verify it matches
    /// @param cloudType The cloud provider type (GCP or Azure)
    /// @param wc The workload collaterals containing PCR measurements and report ID
    /// @param pcrIndex The TPM PCR index to verify against (typically 15 or 16). Different cloud
    ///        providers and TEE types may use different indices:
    ///        - Common practice: PCR 15 for general attestation, PCR 16 for report ID
    /// @param teeData The verified TEE data extracted from the attestation report
    /// @dev Reverts with "Invalid reportID" if:
    ///      - Specified PCR index is not found in the workload collaterals
    ///      - PCR value doesn't match the expected hash extension
    ///      - For SNP: wc.reportId doesn't match teeData.reportID
    ///      - For TDX: RTMR3 doesn't match the expected SHA384 extension of the UUID
    function verifyReportID(
        CloudType cloudType,
        WorkloadCollaterals calldata wc,
        uint256 pcrIndex,
        TEEVerifiedData memory teeData
    )
        internal
        pure
    {
        uint256 len = wc.pcrs.length;
        bool verified;

        for (uint256 i = 0; i < len; i++) {
            if (wc.pcrs[i].index == pcrIndex) {
                // Intel TDX (reportID == 0)
                // TDX attestation reports don't populate reportID field in TEEVerifiedData
                if (teeData.reportID == bytes32(0)) {
                    // Azure TDX: If PCR and rtmr3 are zero, no UUID tracking is performed
                    if (wc.pcrs[i].pcr == bytes32(0) && teeData.tdx.rtmr3.isZero()) {
                        verified = true;
                        break;
                    }

                    // GCP TDX: Verify both PCR and RTMR3 measurements
                    Bytes48 memory reportIdSha384 = Sha2Ext.sha384(wc.reportId);
                    Bytes48 memory expectedTdxRtmr3 =
                        Sha2Ext.sha384(abi.encodePacked(new bytes(48), reportIdSha384.first, reportIdSha384.second));

                    // Compute PCR = SHA256_extend(0, SHA256(reportId))
                    bytes32 reportIdHash = sha256(abi.encodePacked(new bytes(32), sha256(wc.reportId)));

                    // Verify both PCR and RTMR3 match expected values
                    if (wc.pcrs[i].pcr == reportIdHash && expectedTdxRtmr3.equal(teeData.tdx.rtmr3)) {
                        verified = true;
                        break;
                    }
                } else {
                    // AMD SEV-SNP (reportID != 0)
                    // SNP attestation reports populate the reportID field

                    // Azure SNP: PCR[pcrIndex] binding is disabled for Azure deployments.
                    // The TPM-TEE binding is enforced through akPub verification instead.
                    // Therefore, PCR[pcrIndex] may be zero and should be skipped.
                    if (wc.pcrs[i].pcr == bytes32(0) && cloudType == CloudType.Azure) {
                        verified = true;
                        break;
                    }

                    // GCP SNP: Verify that wc.reportId matches teeData.reportID
                    if (wc.reportId.length > 0 && wc.reportId.readBytes32(0) != teeData.reportID) {
                        break;
                    }

                    // Compute expected PCR = SHA256_extend(0, reportID)
                    bytes32 expectedPcr = sha256(abi.encodePacked(new bytes(32), teeData.reportID));

                    // Verify PCR matches expected value
                    if (wc.pcrs[i].pcr != expectedPcr) {
                        break;
                    }

                    verified = true;
                    break;
                }
            }
        }
        if (!verified) {
            revert InvalidReportID();
        }
    }

    /// @notice Parses an AMD SEV-SNP attestation report into TEE verified data.
    /// @dev This function extracts the user report data, report ID, and measurement from
    ///      a raw SEV-SNP attestation report. The report format is fixed and the function
    ///      reads specific byte offsets to extract the required fields.
    /// @param snpReport The raw bytes of the SEV-SNP attestation report.
    /// @return data The parsed TEE verified data containing user report data, report ID, and SNP measurement.
    function snpOutput(bytes memory snpReport) internal pure returns (TEEVerifiedData memory data) {
        data.userReportData = snpReport.readBytes64(80);
        data.reportID = snpReport.readBytes32(320);
        data.snp.measurement = snpReport.readBytes48(144);
        return data;
    }

    /// @notice Checks if a TDX measurement is empty (all fields are zero).
    /// @dev This function verifies that all TDX measurement fields (mrtd, mrseam, rtmr0-rtmr3)
    ///      are zero, indicating an uninitialized or empty measurement.
    /// @param tdx The TDX measurement to check.
    /// @return True if all TDX measurement fields are zero, false otherwise.
    function isEmpty(TdxMeasurement memory tdx) internal pure returns (bool) {
        return tdx.mrtd.isZero() && tdx.mrseam.isZero() && tdx.rtmr0.isZero() && tdx.rtmr1.isZero()
            && tdx.rtmr2.isZero() && tdx.rtmr3.isZero();
    }

    /// @notice Checks if an SNP measurement is empty (measurement field is zero).
    /// @dev This function verifies that the SNP measurement field is zero, indicating
    ///      an uninitialized or empty measurement.
    /// @param snp The SNP measurement to check.
    /// @return True if the SNP measurement is zero, false otherwise.
    function isEmpty(SnpMeasurement memory snp) internal pure returns (bool) {
        return snp.measurement.isZero();
    }

    /// @notice Parses an Intel TDX attestation report output into TEE verified data.
    /// @dev This function extracts TDX-specific measurement fields (mrseam, mrtd, rtmr0-rtmr3)
    ///      and user report data from a raw TDX attestation report output. The function
    ///      checks the quote body type and rejects SGX reports (type 1).
    /// @param output The raw bytes of the TDX attestation report output.
    /// @return data The parsed TEE verified data containing TDX measurements and user report data.
    /// @dev Reverts with UnexpectedSGXReport if the quote body type indicates an SGX report.
    function tdxOutput(bytes memory output) internal pure returns (TEEVerifiedData memory data) {
        uint16 quoteBodyType = uint16(bytes2(output.readBytes2(2)));
        if (quoteBodyType == 1) {
            // sgx, reportData = output[331:395]
            revert UnexpectedSGXReport();
        } else {
            // tdx, reportData = output[531:595]
            data.tdx.mrseam = output.readBytes48(27);
            data.tdx.mrtd = output.readBytes48(147);
            data.tdx.rtmr0 = output.readBytes48(339);
            data.tdx.rtmr1 = output.readBytes48(387);
            data.tdx.rtmr2 = output.readBytes48(435);
            data.tdx.rtmr3 = output.readBytes48(483);
            data.userReportData = output.readBytes64(531);
        }
        return data;
    }

    /// @notice Computes the digest (hash) of a measurement structure.
    /// @dev This function calculates the Keccak256 hash of the ABI-encoded measurement,
    ///      which includes PCRs, TDX measurements, and SNP measurements. The digest is
    ///      used as a unique identifier for golden measurements in the prover registry.
    /// @param gm The measurement structure to compute the digest for.
    /// @return The Keccak256 hash of the encoded measurement.
    function digest(Measurement memory gm) internal pure returns (bytes32) {
        return keccak256(abi.encode(gm));
    }
}
