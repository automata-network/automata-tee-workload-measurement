// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "./utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract AzureSnpTest is TestSetup {
    SnpTestData internal testData;

    function setUp() public override {
        super.setUp();

        string memory path = string.concat(vm.projectRoot(), "/test/testdata/registration_azure_snp.json");
        // Load test data
        testData = TestDataLib.loadSnpData(path);
    }

    function testVerifyAzureSnp() public {
        bytes32 userDataHash = 0xacddde55453462e71daab1341ad7ddc8a5f8ea5e87a0fcacd737265ef3f0555f;

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            abi.encodePacked(testData.reportId),
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        bytes32 measurementHash = workloadVerifier.verifyAttestation(
            userDataHash, TEEType.AmdSevSnp, TeeReportType.ZkSuccinct, CloudType.Azure, testData.report, wc
        );

        bytes memory expectedMeasurement = TestDataLib.getSnpGoldenMeasurementBytes(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(expectedMeasurement);

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }
}
