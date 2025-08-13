// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "../script/utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract GcpTdxTest is TestSetup {
    bytes32 userDataHash = 0xc8e1fafb31b51005b7c05296bf4a766352ff3ac4733ebc1a653c5f28a0254fc2;

    string path = string.concat(vm.projectRoot(), "/test/testdata/registration_gcp_tdx.json");

    function setUp() public override {
        super.setUp();
    }

    function testVerifyGcpTdx() public {
        TdxTestData memory testData = _loadTestData();

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

        bytes32 measurementHash = workloadVerifier.verifyAttestationHash(
            userDataHash, TEEType.IntelTDX, TeeReportType.Solidity, CloudType.GCP, testData.report, wc
        );

        Measurement memory expectedMeasurement = TestDataLib.getTdxGoldenMeasurement(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(abi.encode(expectedMeasurement));

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function testVerifyGcpZkTdx() public {
        TdxTestData memory testData = _loadTestData();

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

        string memory zkPath = string.concat(vm.projectRoot(), "/test/testdata/proof_registration_gcp_tdx_risc0.json");
        ZkProof memory zkReport = TestDataLib.loadZkReport(zkPath);

        bytes32 measurementHash = workloadVerifier.verifyAttestationHash(
            userDataHash, TEEType.IntelTDX, TeeReportType.ZkRiscZero, CloudType.GCP, abi.encode(zkReport), wc
        );

        Measurement memory expectedMeasurement = TestDataLib.getTdxGoldenMeasurement(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(abi.encode(expectedMeasurement));

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function _loadTestData() internal view returns (TdxTestData memory) {
        return TestDataLib.loadTdxData(path);
    }
}
