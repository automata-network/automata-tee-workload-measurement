// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "./utils/TestDataLib.sol";
import "forge-std/console.sol";

import {TEEType, TeeReportType, CloudType} from "../src/lib/LibTEE.sol";

contract GcpSnpTest is TestSetup {
    function setUp() public override {
        super.setUp();
    }

    function testVerifyGcpSnp() public {
        bytes32 userDataHash = 0xa4099be3cfdb31b19e300e3b68cb9c9908bcc33696b66ca551b9489a912c4458;

        SnpTestData memory testData =
            _loadTestData(string.concat(vm.projectRoot(), "/test/testdata/registration_gcp_snp.json"));

        // pinned July 22, 2025, 1840h UTC+8
        vm.warp(1753180800);

        // Upsert Google EK/AK CA Root
        bytes memory googleCa = testData.tpmCerts[testData.tpmCerts.length - 1];
        vm.prank(owner);
        tpmAttestation.addCA(googleCa);

        WorkloadCollaterals memory wc = TestDataLib.getWc(
            abi.encodePacked(testData.reportId),
            testData.akPub,
            testData.tpmQuote,
            testData.tpmSignature,
            testData.tpmCerts,
            testData.tpmPcrs
        );

        string memory path = string.concat(vm.projectRoot(), "/test/testdata/proof_registration_gcp_snp_risc0.json");
        ZkProof memory zkReport = TestDataLib.loadZkReport(path);

        bytes32 measurementHash = workloadVerifier.verifyAttestationHash(
            userDataHash, TEEType.AmdSevSnp, TeeReportType.ZkRiscZero, CloudType.GCP, abi.encode(zkReport), wc
        );

        bytes memory expectedMeasurement = TestDataLib.getSnpGoldenMeasurementBytes(testData.goldenMeasurement);
        bytes32 expectedMeasurementHash = keccak256(expectedMeasurement);

        assertEq(measurementHash, expectedMeasurementHash, "Measurement hash mismatch");
    }

    function _loadTestData(string memory path) internal view returns (SnpTestData memory) {
        return TestDataLib.loadSnpData(path);
    }
}
