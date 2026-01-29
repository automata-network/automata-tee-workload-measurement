// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import "forge-std/console.sol";
import {TestSetup} from "./utils/TestSetup.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Base64} from "solady/utils/Base64.sol";
import {Measurement} from "../src/lib/LibTEE.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CVMRegistry, CVMConfig, ICVMRegistry} from "../src/usecases/CVMRegistry.sol";

contract CvmAzureTest is TestSetup {
    using stdJson for string;

    function testAzureTdxCvm() public {
        _runCvmWorkflowTest(
            CvmTestConfig({
                registerCalldataPath: "/test/testdata/azure/tdx/solidity/registration_calldata.json",
                refreshCalldataPath: "/test/testdata/azure/tdx/solidity/refresh_calldata.json",
                rotateCalldataPath: "/test/testdata/azure/tdx/solidity/rotate_calldata.json",
                goldenMeasurementPath: "/test/testdata/azure/tdx/solidity/golden-measurement.json",
                initialCvmIdentityHash: 0x495f4220be7b9786aa0daea572ee1f0dec28ee42288458e81c1f29eb5069f260,
                rotatedCvmIdentityHash: 0x2d083b8854e1f2dfe493f62e27746abab2ba2b806bcfb04acad899c85640c2aa,
                tpmAkRootCa: "",
                isBase64Encoded: true,
                pinnedTimestamp: 0,
                refreshTimeAdvance: 10 days,
                expiryTimeAdvance: 60 days
            })
        );
    }

    function testAzureSevSnp() public {
        _runCvmWorkflowTest(
            CvmTestConfig({
                registerCalldataPath: "/test/testdata/azure/snp/registration_calldata.json",
                refreshCalldataPath: "/test/testdata/azure/snp/refresh_calldata.json",
                rotateCalldataPath: "/test/testdata/azure/snp/rotate_calldata.json",
                goldenMeasurementPath: "/test/testdata/azure/snp/golden-measurement.json",
                initialCvmIdentityHash: 0xf8b899f1ca1f2b600619ac798f63f72169a8d7c8f09cc5e7aedf32f75452c9d4,
                rotatedCvmIdentityHash: 0x3ef52946bf031816faff58e169a38af8c215b6b3e35e007921bd8ec62ecf0dbc,
                tpmAkRootCa: "",
                isBase64Encoded: true,
                pinnedTimestamp: 0,
                refreshTimeAdvance: 10 days,
                expiryTimeAdvance: 60 days
            })
        );
    }
}
