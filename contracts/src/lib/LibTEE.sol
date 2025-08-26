// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {MeasureablePcr, Pcr} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {Pubkey} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";
import {WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import "./LibBytes.sol";
import {Sha2Ext} from "./Sha2Ext.sol";

using LibBytes for bytes;
using LibBytes for bytes32;
using LibTEE for Measurement global;
using LibTEE for TEEType global;
using LibTEE for CloudType global;
using LibTEE for TdxMeasurement global;
using LibTEE for SnpMeasurement global;

enum TEEType {
    Mock,
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
    Pubkey akPub; // verified akPub
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

library LibTEE {
    // gcp&tdx: reportId=0, wc.reportId=uuid, pcr16=sha256_extend(0, sha256(uuid)), rtmr3=sha384_extend(0, sha384(uuid))
    // gcp&snp: reportId=wc.report=snp.reportId, pcr16=extend(0, reportId)
    // azure&tdx: reportID=0, wc.reportId=bytes16(0), pcr16=extend(0), rtmr3=0
    // azure&snp: pcr16=extend(0, reportId)
    function verifyReportID(WorkloadCollaterals calldata wc, TEEVerifiedData memory teeData) internal pure {
        uint256 len = wc.pcrs.length;
        bool verified;

        for (uint256 i = 0; i < len; i++) {
            if (wc.pcrs[i].index == 15) {
                if (teeData.reportID == bytes32(0)) {
                    // non-snp
                    if (wc.pcrs[i].pcr == bytes32(0)) {
                        // no need to check
                        verified = true;
                        break;
                    }
                    Bytes48 memory reportIdSha384 = Sha2Ext.sha384(wc.reportId);
                    Bytes48 memory expectedTdxRtmr3;
                    if (!teeData.tdx.rtmr3.isZero()) {
                        expectedTdxRtmr3 =
                            Sha2Ext.sha384(abi.encodePacked(new bytes(48), reportIdSha384.first, reportIdSha384.second));
                    }

                    bytes32 reportIdHash = sha256(abi.encodePacked(new bytes(32), sha256(wc.reportId)));
                    if (wc.pcrs[i].pcr == reportIdHash && expectedTdxRtmr3.equal(teeData.tdx.rtmr3)) {
                        verified = true;
                        break;
                    }
                } else {
                    if (wc.pcrs[i].pcr == bytes32(0)) {
                        // auzre & snp
                        verified = true;
                        break;
                    }
                    if (wc.reportId.length != 32 || wc.reportId.readBytes32(0) != teeData.reportID) {
                        break;
                    }
                    bytes32 expectedPcr = sha256(abi.encodePacked(new bytes(32), teeData.reportID));
                    if (wc.pcrs[i].pcr != expectedPcr) {
                        break;
                    }
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) {
            revert("Invalid reportID");
        }
    }

    // output is the snp attestation report
    function snpOutput(bytes memory snpReport) internal pure returns (TEEVerifiedData memory data) {
        data.userReportData = snpReport.readBytes64(80);
        data.reportID = snpReport.readBytes32(320);
        data.snp.measurement = snpReport.readBytes48(144);
        return data;
    }

    function isEmpty(TdxMeasurement memory tdx) internal pure returns (bool) {
        return tdx.mrtd.isZero() && tdx.mrseam.isZero() && tdx.rtmr0.isZero() && tdx.rtmr1.isZero()
            && tdx.rtmr2.isZero() && tdx.rtmr3.isZero();
    }

    function isEmpty(SnpMeasurement memory snp) internal pure returns (bool) {
        return snp.measurement.isZero();
    }

    function tdxOutput(bytes memory output) internal pure returns (TEEVerifiedData memory data) {
        uint16 quoteBodyType = uint16(bytes2(output.readBytes2(2)));
        if (quoteBodyType == 1) {
            // sgx, reportData = output[331:395]
            data.userReportData = output.readBytes64(331);
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

    function digest(Measurement memory gm) internal pure returns (bytes32) {
        return keccak256(abi.encode(gm));
    }
}
