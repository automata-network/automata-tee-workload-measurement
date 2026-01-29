// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import "forge-std/console.sol";
import {TestSetup} from "./utils/TestSetup.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Base64} from "solady/utils/Base64.sol";
import {Measurement} from "../src/lib/LibTEE.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CVMRegistry, CVMConfig} from "../src/usecases/CVMRegistry.sol";

contract CvmGcpTest is TestSetup {
    using stdJson for string;

    function testGcpTdxCvm() public {
        bytes memory googleCa = vm.readFileBinary(string.concat(vm.projectRoot(), "/test/testdata/gcp/tpmAkRoot.der"));

        _runCvmWorkflowTest(
            CvmTestConfig({
                registerCalldataPath: "/test/testdata/gcp/tdx/registration_calldata.json",
                refreshCalldataPath: "/test/testdata/gcp/tdx/refresh_calldata.json",
                rotateCalldataPath: "/test/testdata/gcp/tdx/rotate_calldata.json",
                goldenMeasurementPath: "/test/testdata/gcp/tdx/golden-measurement.json",
                initialCvmIdentityHash: 0x08a1d4f1acc3452aac599c7b57ec21eb7efb8a3898f3b0c256432eb6d3dec8ff,
                rotatedCvmIdentityHash: 0x540b38ecce62cde8eaaded9095742c3d041a2088483e5fd33920505c68b4c43d,
                tpmAkRootCa: googleCa,
                isBase64Encoded: true,
                pinnedTimestamp: 1768975500, // January 21st, 2026, 0605h UTC
                refreshTimeAdvance: 10 days,
                expiryTimeAdvance: 60 days
            })
        );
    }

    function testGcpSevSnp() public {
        bytes memory googleCa = vm.readFileBinary(string.concat(vm.projectRoot(), "/test/testdata/gcp/tpmAkRoot.der"));

        _runCvmWorkflowTest(
            CvmTestConfig({
                registerCalldataPath: "/test/testdata/gcp/snp/registration_calldata.json",
                refreshCalldataPath: "/test/testdata/gcp/snp/refresh_calldata.json",
                rotateCalldataPath: "/test/testdata/gcp/snp/rotate_calldata.json",
                goldenMeasurementPath: "/test/testdata/gcp/snp/golden-measurement.json",
                initialCvmIdentityHash: 0xc46b28a893b7f3a16ff5ed632b5471baad32820ab04bb393fcdd98b1729968e7,
                rotatedCvmIdentityHash: 0xf45b5559278e4118afd12659c771a1f7c166bd8ee67b110d39e057515cbdcbee,
                tpmAkRootCa: googleCa,
                isBase64Encoded: true,
                pinnedTimestamp: 1768977000, // January 21st, 2026, 0630h UTC
                refreshTimeAdvance: 10 days,
                expiryTimeAdvance: 60 days
            })
        );
    }
}
