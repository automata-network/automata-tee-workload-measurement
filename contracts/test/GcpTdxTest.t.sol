// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "./utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract GcpTdxTest is TestSetup {
    function setUp() public override {
        super.setUp();
    }

    function testVerifyGcpTdx() public {
        bytes32 userDataHash = 0xc8e1fafb31b51005b7c05296bf4a766352ff3ac4733ebc1a653c5f28a0254fc2;

        string memory path = string.concat(vm.projectRoot(), "/test/testdata/registration_gcp_tdx.json");
        TdxTestData memory testData = _loadTestData(path);

        // pinned July 22, 2025, 1840h UTC+8
        vm.warp(1753180800);

        // Upsert Google EK/AK CA Root
        bytes memory googleCa = testData.tpmCerts[testData.tpmCerts.length - 1];
        vm.prank(owner);
        tpmAttestation.addCA(googleCa);

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            testData.reportId,
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        bytes32 measurementHash = workloadVerifier.verifyAttestation(
            userDataHash, TEEType.IntelTDX, TeeReportType.Solidity, CloudType.GCP, testData.report, wc
        );

        bytes memory expectedMeasurement = TestDataLib.getTdxGoldenMeasurementBytes(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(expectedMeasurement);

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function _loadTestData(string memory path) internal view returns (TdxTestData memory) {
        return TestDataLib.loadTdxData(path);
    }
}
