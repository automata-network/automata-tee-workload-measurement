// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.15;

import {Pcr, WorkloadCollaterals} from "../interfaces/IWorkloadVerifier.sol";
import {MeasureablePcr} from "../interfaces/ITpmAttestation.sol";
import "./LibX509.sol";
import "./LibBytes.sol";
import {Sha2Ext} from "./Sha2Ext.sol";

using LibBytes for bytes;
using LibBytes for bytes32;
using LibTEE for GoldenMeasurement global;
using LibTEE for TEEType global;
using LibTEE for CloudType global;

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

struct GoldenMeasurement {
    Pcr[] pcrs;
    GoldenMeasurementTdx tdx;
    GoldenMeasurementSnp snp;
}

struct GoldenMeasurementTdx {
    Bytes48 mrtd;
    Bytes48 mrseam;
    Bytes48 rtmr0;
    Bytes48 rtmr1;
    Bytes48 rtmr2;
    Bytes48 rtmr3;
}

struct GoldenMeasurementSnp {
    Bytes48 measurement;
}

struct TEEVerifiedData {
    // TEE Report Data
    Bytes64 userReportData;
    // VM Instance-level unique ID
    // TDX: UUID
    // SNP: sev-snp.report_id
    bytes32 reportID;
    CertPubkey akPub; // verified akPub
    TdxVerifiedData tdx;
    SnpVerifiedData snp;
}

struct SnpVerifiedData {
    Bytes48 measurement;
}

struct TdxVerifiedData {
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
            if (wc.pcrs[i].index == 16) {
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

    // function toString(TEEVerifiedData memory data) public pure returns (string memory) {
    //     return string(
    //         abi.encodePacked(
    //             "{userReportData: ",
    //             data.userReportData.toString(),
    //             ", reportID: ",
    //             data.reportID.toString(),
    //             ", akPub: ",
    //             toString(data.akPub),
    //             ", tdx: ",
    //             toString(data.tdx),
    //             ", snp: ",
    //             toString(data.snp),
    //             "}"
    //         )
    //     );
    // }

    // function toString(CertPubkey memory key) public pure returns (string memory) {
    //     return string(abi.encodePacked("{data: ", key.data.toString(), "}"));
    // }

    // function toString(SnpVerifiedData memory snp) public pure returns (string memory) {
    //     return string(abi.encodePacked("{measurement: ", snp.measurement.toString(), "}"));
    // }

    // function toString(TdxVerifiedData memory tdx) public pure returns (string memory) {
    //     bytes memory output = abi.encodePacked(
    //         "{mrtd: ",
    //         tdx.mrtd.toString(),
    //         ", mrseam: ",
    //         tdx.mrseam.toString(),
    //         ", rtmr0: ",
    //         tdx.rtmr0.toString(),
    //         ", rtmr1: ",
    //         tdx.rtmr1.toString(),
    //         ", rtmr2: ",
    //         tdx.rtmr2.toString(),
    //         ", rtmr3: ",
    //         tdx.rtmr3.toString(),
    //         "}"
    //     );
    //     return string(output);
    // }

    function tdxOutput(bytes memory output) internal pure returns (TEEVerifiedData memory data) {
        bytes4 tee = output.readBytes4(2);
        if (tee == 0x00000000) {
            // sgx, reportData = output[333:397]
            data.userReportData = output.readBytes64(333);
        } else {
            // tdx, reportData = output[533:597]
            data.tdx.mrseam = output.readBytes48(29);
            data.tdx.mrtd = output.readBytes48(149);
            data.tdx.rtmr0 = output.readBytes48(341);
            data.tdx.rtmr1 = output.readBytes48(389);
            data.tdx.rtmr2 = output.readBytes48(437);
            data.tdx.rtmr3 = output.readBytes48(485);
            data.userReportData = output.readBytes64(533);
        }
        return data;
    }

    function digest(GoldenMeasurement memory gm) internal pure returns (bytes32) {
        return keccak256(abi.encode(gm));
    }

    function goldenMeasurement(
        MeasureablePcr[] calldata mpcrs,
        TdxVerifiedData memory teeTdx,
        SnpVerifiedData memory teeSnp
    ) internal pure returns (GoldenMeasurement memory) {
        GoldenMeasurementTdx memory tdx = toGoldenMeasurementTdx(teeTdx);
        GoldenMeasurementSnp memory snp = toGoldenMeasurementSnp(teeSnp);
        GoldenMeasurement memory gm = GoldenMeasurement({pcrs: toPcr(mpcrs), tdx: tdx, snp: snp});
        return gm;
    }

    function toGoldenMeasurementTdx(TdxVerifiedData memory tdx)
        internal
        pure
        returns (GoldenMeasurementTdx memory output)
    {
        output.mrtd = tdx.mrtd;
        output.mrseam = tdx.mrseam;
        output.rtmr0 = tdx.rtmr0;
        output.rtmr1 = tdx.rtmr1;
        output.rtmr2 = tdx.rtmr2;
        output.rtmr3 = tdx.rtmr3;
    }

    function toGoldenMeasurementSnp(SnpVerifiedData memory snp)
        internal
        pure
        returns (GoldenMeasurementSnp memory output)
    {
        output.measurement = snp.measurement;
    }

    function toPcr(MeasureablePcr[] calldata mpcrs) internal pure returns (Pcr[] memory) {
        // Cache array length to avoid multiple storage reads
        uint256 mpcrsLength = mpcrs.length;
        Pcr[] memory pcrs = new Pcr[](mpcrsLength);

        // Use unchecked to save gas on bounds checking where we know it's safe
        unchecked {
            for (uint256 i = 0; i < mpcrsLength; i++) {
                // Cache the current MeasureablePcr to avoid multiple calldata accesses
                MeasureablePcr calldata currentMpcr = mpcrs[i];

                // Verify events before allocating memory for arrays
                require(verifyEvents(currentMpcr), "Invalid all events");

                // Cache the measureEventsIdx length
                uint256 eventsIdxLength = currentMpcr.measureEventsIdx.length;

                // Only allocate memory if there are events to process
                bytes32[] memory measureEvents = new bytes32[](eventsIdxLength);
                uint256[] memory measureEventsIdx = new uint256[](eventsIdxLength);

                // Process events only if there are any
                if (eventsIdxLength > 0) {
                    uint256 allEventsLength = currentMpcr.allEvents.length;

                    for (uint256 j = 0; j < eventsIdxLength; j++) {
                        uint256 eventIdx = currentMpcr.measureEventsIdx[j];
                        require(eventIdx < allEventsLength, "Invalid event index");
                        measureEvents[j] = currentMpcr.allEvents[eventIdx];
                        measureEventsIdx[j] = eventIdx;
                    }
                }

                // Create the PCR with the correct values
                pcrs[i] = Pcr({
                    index: currentMpcr.index,
                    pcr: currentMpcr.measurePcr ? currentMpcr.pcr : bytes32(0),
                    measureEvents: measureEvents,
                    measureEventsIdx: measureEventsIdx
                });
            }
        }
        return pcrs;
    }

    function verifyEvents(MeasureablePcr calldata mpcr) internal pure returns (bool) {
        // Early return conditions
        if (mpcr.pcr == bytes32(0)) {
            return true;
        }

        uint256 allEventsLength = mpcr.allEvents.length;
        if (allEventsLength == 0) {
            return true;
        }

        bytes32 before = bytes32(0);
        // Use unchecked for loop operations to save gas
        unchecked {
            for (uint256 i = 0; i < allEventsLength; i++) {
                before = sha256(abi.encodePacked(before, mpcr.allEvents[i]));
            }
        }

        return before == mpcr.pcr;
    }

    // function name(CloudType ct) internal pure returns (string memory) {
    //     if (ct == CloudType.GCP) {
    //         return "gcp";
    //     } else if (ct == CloudType.Azure) {
    //         return "azure";
    //     } else {
    //         revert("Invalid CloudType");
    //     }
    // }

    // function name(TEEType tt) internal pure returns (string memory) {
    //     if (tt == TEEType.Mock) {
    //         return "mock";
    //     } else if (tt == TEEType.IntelTDX) {
    //         return "tdx";
    //     } else if (tt == TEEType.AmdSevSnp) {
    //         return "snp";
    //     } else {
    //         revert("Invalid TEEType");
    //     }
    // }

    // function toString(GoldenMeasurementTdx memory gm) internal pure returns (string memory) {
    //     return string(
    //         abi.encodePacked(
    //             "{mrtd: ",
    //             gm.mrtd.toString(),
    //             ", mrseam: ",
    //             gm.mrseam.toString(),
    //             ", rtmr0: ",
    //             gm.rtmr0.toString(),
    //             ", rtmr1: ",
    //             gm.rtmr1.toString(),
    //             ", rtmr2: ",
    //             gm.rtmr2.toString(),
    //             ", rtmr3: ",
    //             gm.rtmr3.toString(),
    //             "}"
    //         )
    //     );
    // }

    // function toString(GoldenMeasurementSnp memory gm) internal pure returns (string memory) {
    //     return string(abi.encodePacked("{measurement: ", gm.measurement.toString(), "}"));
    // }

    // function toString(GoldenMeasurement memory gm) public pure returns (string memory) {
    //     bytes memory output = abi.encodePacked("{pcrs:[");
    //     for (uint256 i = 0; i < gm.pcrs.length; i++) {
    //         output = abi.encodePacked(output, gm.pcrs[i].toString());
    //         if (i < gm.pcrs.length - 1) {
    //             output = abi.encodePacked(output, ",");
    //         }
    //     }
    //     output = abi.encodePacked(output, "], tdx:", toString(gm.tdx), ",snp:", toString(gm.snp), "}");
    //     return string(output);
    // }

    // function decodeZkProof(bytes memory zkProof) public pure returns (ZkProof memory) {
    //     return abi.decode(zkProof, (ZkProof));
    // }
}
