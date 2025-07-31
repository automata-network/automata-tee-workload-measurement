// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "./utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract AzureTdxTest is TestSetup {
    bytes32 userDataHash = 0xacddde55453462e71daab1341ad7ddc8a5f8ea5e87a0fcacd737265ef3f0555f;
    string path = string.concat(vm.projectRoot(), "/test/testdata/registration_azure_tdx.json");

    function setUp() public override {
        super.setUp();
    }

    function testVerifyAzureTdx() public {
        TdxTestData memory testData = _loadTestData();

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            testData.reportId,
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        bytes32 measurementHash = workloadVerifier.verifyAttestation(
            userDataHash, TEEType.IntelTDX, TeeReportType.Solidity, CloudType.Azure, testData.report, wc
        );

        bytes memory expectedMeasurement = TestDataLib.getTdxGoldenMeasurementBytes(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(expectedMeasurement);

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function testVerifyAzureZkTdx() public {
        TdxTestData memory testData = _loadTestData();

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            testData.reportId,
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        string memory zkPath = string.concat(vm.projectRoot(), "/test/testdata/proof_registration_azure_tdx_risc0.json");
        ZkProof memory zkReport = TestDataLib.loadZkReport(zkPath);

        bytes32 measurementHash = workloadVerifier.verifyAttestation(
            userDataHash, TEEType.IntelTDX, TeeReportType.ZkRiscZero, CloudType.Azure, abi.encode(zkReport), wc
        );

        bytes memory expectedMeasurement = TestDataLib.getTdxGoldenMeasurementBytes(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(expectedMeasurement);

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function _loadTestData() internal view returns (TdxTestData memory) {
        return TestDataLib.loadTdxData(path);
    }
}
