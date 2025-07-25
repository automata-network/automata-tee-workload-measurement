// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {stdJson} from "forge-std/StdJson.sol";
import {Vm} from "forge-std/Vm.sol";
import {WorkloadCollaterals, MeasureablePcr} from "../../src/lib/LibTPM.sol";
import {GoldenMeasurement, GoldenMeasurementTdx, GoldenMeasurementSnp, Pcr, ZkProof} from "../../src/lib/LibTEE.sol";
import {LibBytes} from "../../src/lib/LibBytes.sol";

struct SnpTestData {
    bytes akPub;
    SnpGoldenMeasurement goldenMeasurement;
    bytes report;
    bytes32 reportId;
    bytes[] tpmCerts;
    TestMeasurablePcr[] tpmPcrs;
    bytes tpmQuote;
    bytes tpmSignature;
    bytes[] vekCerts;
}

struct TdxTestData {
    bytes akPub;
    TdxGoldenMeasurement goldenMeasurement;
    bytes report;
    bytes reportId;
    bytes[] tpmCerts;
    TestMeasurablePcr[] tpmPcrs;
    bytes tpmQuote;
    bytes tpmSignature;
    bytes[] vekCerts;
}

struct SnpGoldenMeasurement {
    TestPcr[] pcrs;
    Snp snp;
}

struct TdxGoldenMeasurement {
    TestPcr[] pcrs;
    Tdx tdx;
}

struct Snp {
    bytes measurement;
}

struct Tdx {
    bytes mrseam;
    bytes mrtd;
    bytes rtmr0;
    bytes rtmr1;
    bytes rtmr2;
    bytes rtmr3;
}

struct TestMeasurablePcr {
    bytes32[] allEvents;
    uint256 index;
    uint256[] measureEventsIdx;
    bool measurePcr;
    bytes32 pcr;
}

struct TestPcr {
    uint256 index;
    uint256[] measureEventsIdx;
    bytes32[] measuredEvents;
    bytes32 pcr;
}

library TestDataLib {
    address constant HEVM_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
    Vm constant internalVm = Vm(HEVM_ADDRESS);

    using stdJson for string;
    using LibBytes for bytes;

    // Helper function to parse hex string to uint256
    function parseHexString(string memory hexStr) internal pure returns (uint256) {
        bytes memory hexBytes = bytes(hexStr);
        require(hexBytes.length >= 2 && hexBytes[0] == "0" && hexBytes[1] == "x", "Invalid hex string");

        uint256 result = 0;
        for (uint256 i = 2; i < hexBytes.length; i++) {
            result = result * 16;
            uint8 digit = uint8(hexBytes[i]);
            if (digit >= 48 && digit <= 57) {
                // 0-9
                result += digit - 48;
            } else if (digit >= 65 && digit <= 70) {
                // A-F
                result += digit - 55;
            } else if (digit >= 97 && digit <= 102) {
                // a-f
                result += digit - 87;
            } else {
                revert("Invalid hex character");
            }
        }
        return result;
    }

    // Helper function to parse hex string arrays (for measure_events_idx)
    function parseHexStringArray(string memory json, string memory key) internal view returns (uint256[] memory) {
        if (!json.keyExists(key)) {
            return new uint256[](0);
        }

        // Try to determine array length by checking each index
        uint256 length = 0;
        while (true) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(length), "]");
            if (!json.keyExists(indexKey)) {
                break;
            }
            length++;
        }

        if (length == 0) {
            return new uint256[](0);
        }

        uint256[] memory result = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(i), "]");
            string memory hexString = json.readString(indexKey);
            result[i] = parseHexString(hexString);
        }

        return result;
    }

    // Helper function to parse TPM PCRs array with hex string handling
    function parseTmpPcrsArray(string memory json, string memory key)
        internal
        view
        returns (TestMeasurablePcr[] memory)
    {
        // Try to parse each index until we get an error to determine array length
        uint256 length = 0;
        while (true) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(length), "].index");
            if (!json.keyExists(indexKey)) {
                break;
            }
            length++;
        }

        TestMeasurablePcr[] memory pcrs = new TestMeasurablePcr[](length);

        for (uint256 i = 0; i < length; i++) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(i), "]");

            // Parse hex string index
            string memory hexIndex = json.readString(string.concat(indexKey, ".index"));
            pcrs[i].index = parseHexString(hexIndex);

            // Parse other fields
            pcrs[i].pcr = json.readBytes32(string.concat(indexKey, ".pcr"));
            pcrs[i].allEvents = json.readBytes32Array(string.concat(indexKey, ".all_events"));
            pcrs[i].measurePcr = json.readBool(string.concat(indexKey, ".measure_pcr"));
            pcrs[i].measureEventsIdx = parseHexStringArray(json, string.concat(indexKey, ".measure_events_idx"));
        }

        return pcrs;
    }

    // Helper function to parse golden measurement PCRs array with hex string handling
    function parseGoldenPcrsArray(string memory json, string memory key) internal view returns (TestPcr[] memory) {
        // Try to parse each index until we get an error to determine array length
        uint256 length = 0;
        while (true) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(length), "].index");
            if (!json.keyExists(indexKey)) {
                break;
            }
            length++;
        }

        TestPcr[] memory pcrs = new TestPcr[](length);

        for (uint256 i = 0; i < length; i++) {
            string memory indexKey = string.concat(key, "[", internalVm.toString(i), "]");

            // Parse hex string index
            string memory hexIndex = json.readString(string.concat(indexKey, ".index"));
            pcrs[i].index = parseHexString(hexIndex);

            // Parse other fields
            pcrs[i].pcr = json.readBytes32(string.concat(indexKey, ".pcr"));
            pcrs[i].measuredEvents = json.readBytes32Array(string.concat(indexKey, ".measure_events"));
            pcrs[i].measureEventsIdx = parseHexStringArray(json, string.concat(indexKey, ".measure_events_idx"));
        }

        return pcrs;
    }

    // Helper function to parse TDX golden measurement
    function parseTdxGoldenMeasurement(string memory json, string memory key)
        internal
        view
        returns (TdxGoldenMeasurement memory)
    {
        TdxGoldenMeasurement memory measurement;

        // Parse PCRs array
        measurement.pcrs = parseGoldenPcrsArray(json, string.concat(key, ".pcrs"));

        // Parse TDX measurement
        string memory tdxKey = string.concat(key, ".tdx");
        measurement.tdx.mrtd = json.readBytes(string.concat(tdxKey, ".mrtd"));
        measurement.tdx.mrseam = json.readBytes(string.concat(tdxKey, ".mrseam"));
        measurement.tdx.rtmr0 = json.readBytes(string.concat(tdxKey, ".rtmr0"));
        measurement.tdx.rtmr1 = json.readBytes(string.concat(tdxKey, ".rtmr1"));
        measurement.tdx.rtmr2 = json.readBytes(string.concat(tdxKey, ".rtmr2"));
        measurement.tdx.rtmr3 = json.readBytes(string.concat(tdxKey, ".rtmr3"));

        return measurement;
    }

    // Helper function to parse SNP golden measurement
    function parseSnpGoldenMeasurement(string memory json, string memory key)
        internal
        view
        returns (SnpGoldenMeasurement memory)
    {
        SnpGoldenMeasurement memory measurement;

        // Parse PCRs array (same as TDX)
        measurement.pcrs = parseGoldenPcrsArray(json, string.concat(key, ".pcrs"));

        // Parse SNP measurement
        string memory snpKey = string.concat(key, ".snp");
        measurement.snp.measurement = json.readBytes(string.concat(snpKey, ".measurement"));

        return measurement;
    }

    function loadTdxData(string memory path) internal view returns (TdxTestData memory testData) {
        string memory json = internalVm.readFile(path);

        // Parse simple fields normally
        testData.akPub = json.readBytes(".ak_pub");
        testData.report = json.readBytes(".report");
        testData.reportId = json.readBytes(".report_id");
        testData.tpmQuote = json.readBytes(".tpm_quote");
        testData.tpmSignature = json.readBytes(".tpm_signature");
        testData.tpmCerts = json.readBytesArray(".tpm_certs");
        testData.vekCerts = json.readBytesArray(".vek_certs");

        // Parse complex fields with hex handling
        testData.tpmPcrs = parseTmpPcrsArray(json, ".tpm_pcrs");
        testData.goldenMeasurement = parseTdxGoldenMeasurement(json, ".golden_measurement");
    }

    function loadSnpData(string memory path) internal view returns (SnpTestData memory testData) {
        string memory json = internalVm.readFile(path);

        // Parse simple fields normally
        testData.akPub = json.readBytes(".ak_pub");
        testData.report = json.readBytes(".report");
        testData.reportId = json.readBytes32(".report_id");
        testData.tpmQuote = json.readBytes(".tpm_quote");
        testData.tpmSignature = json.readBytes(".tpm_signature");
        testData.tpmCerts = json.readBytesArray(".tpm_certs");
        testData.vekCerts = json.readBytesArray(".vek_certs");

        // Parse complex fields with hex handling
        testData.tpmPcrs = parseTmpPcrsArray(json, ".tpm_pcrs");
        testData.goldenMeasurement = parseSnpGoldenMeasurement(json, ".golden_measurement");
    }

    function loadZkReport(string memory path) internal view returns (ZkProof memory zkReport) {
        string memory json = internalVm.readFile(path);
        zkReport.output = json.readBytes(".raw_proof.journal");
        zkReport.proofBytes = json.readBytes(".onchain_proof");
    }

    function getWc(
        bytes memory reportId,
        bytes memory akPub,
        bytes memory tpmQuote,
        bytes memory tpmSignature,
        bytes[] memory tpmCerts,
        TestMeasurablePcr[] memory tpmPcrs
    ) internal pure returns (WorkloadCollaterals memory wc) {
        wc.reportId = reportId;
        wc.akPub = akPub;
        wc.tpmQuote = tpmQuote;
        wc.tpmSignature = tpmSignature;
        wc.certs = tpmCerts;

        uint256 n = tpmPcrs.length;
        wc.pcrs = new MeasureablePcr[](n);
        for (uint256 i = 0; i < n; i++) {
            wc.pcrs[i] = MeasureablePcr({
                allEvents: tpmPcrs[i].allEvents,
                index: tpmPcrs[i].index,
                measureEventsIdx: tpmPcrs[i].measureEventsIdx,
                measurePcr: tpmPcrs[i].measurePcr,
                pcr: tpmPcrs[i].pcr
            });
        }
    }

    function getTdxGoldenMeasurementBytes(TdxGoldenMeasurement memory tdxGoldenMeasurement)
        internal
        pure
        returns (bytes memory encoded)
    {
        GoldenMeasurement memory gm;

        // TDX
        gm.tdx.mrtd = tdxGoldenMeasurement.tdx.mrtd.toBytes48();
        gm.tdx.mrseam = tdxGoldenMeasurement.tdx.mrseam.toBytes48();
        gm.tdx.rtmr0 = tdxGoldenMeasurement.tdx.rtmr0.toBytes48();
        gm.tdx.rtmr1 = tdxGoldenMeasurement.tdx.rtmr1.toBytes48();
        gm.tdx.rtmr2 = tdxGoldenMeasurement.tdx.rtmr2.toBytes48();
        gm.tdx.rtmr3 = tdxGoldenMeasurement.tdx.rtmr3.toBytes48();

        // PCRs
        gm.pcrs = new Pcr[](tdxGoldenMeasurement.pcrs.length);
        for (uint256 i = 0; i < tdxGoldenMeasurement.pcrs.length; i++) {
            gm.pcrs[i].index = tdxGoldenMeasurement.pcrs[i].index;
            gm.pcrs[i].pcr = tdxGoldenMeasurement.pcrs[i].pcr;
            gm.pcrs[i].measureEvents = tdxGoldenMeasurement.pcrs[i].measuredEvents;
            gm.pcrs[i].measureEventsIdx = tdxGoldenMeasurement.pcrs[i].measureEventsIdx;
        }

        encoded = abi.encode(gm);
    }

    function getSnpGoldenMeasurementBytes(SnpGoldenMeasurement memory snpGoldenMeasurement)
        internal
        pure
        returns (bytes memory encoded)
    {
        GoldenMeasurement memory gm;

        // SNP
        gm.snp.measurement = snpGoldenMeasurement.snp.measurement.toBytes48();

        // PCRs
        gm.pcrs = new Pcr[](snpGoldenMeasurement.pcrs.length);
        for (uint256 i = 0; i < snpGoldenMeasurement.pcrs.length; i++) {
            gm.pcrs[i].index = snpGoldenMeasurement.pcrs[i].index;
            gm.pcrs[i].pcr = snpGoldenMeasurement.pcrs[i].pcr;
            gm.pcrs[i].measureEvents = snpGoldenMeasurement.pcrs[i].measuredEvents;
            gm.pcrs[i].measureEventsIdx = snpGoldenMeasurement.pcrs[i].measureEventsIdx;
        }

        encoded = abi.encode(gm);
    }
}
