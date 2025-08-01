// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "../script/utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract AzureSnpTest is TestSetup {
    function setUp() public override {
        super.setUp();
    }

    function testVerifyAzureSnp() public {
        bytes32 userDataHash = 0xbd5f88a79dd2ae29392a9d85597be119d8ba406505ae65d139c814de928911ec;

        SnpTestData memory testData =
            _loadTestData(string.concat(vm.projectRoot(), "/test/testdata/registration_azure_snp.json"));

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            abi.encodePacked(testData.reportId),
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        string memory path = string.concat(vm.projectRoot(), "/test/testdata/proof_registration_azure_snp_risc0.json");
        ZkProof memory zkReport = TestDataLib.loadZkReport(path);

        bytes32 measurementHash = workloadVerifier.verifyAttestationHash(
            userDataHash, TEEType.AmdSevSnp, TeeReportType.ZkRiscZero, CloudType.Azure, abi.encode(zkReport), wc
        );

        GoldenMeasurement memory expectedMeasurement = TestDataLib.getSnpGoldenMeasurement(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(abi.encode(expectedMeasurement));

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function _loadTestData(string memory path) internal view returns (SnpTestData memory) {
        return TestDataLib.loadSnpData(path);
    }
}
