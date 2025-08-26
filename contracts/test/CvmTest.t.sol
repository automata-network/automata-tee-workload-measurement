// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {TestSetup} from "./utils/TestSetup.sol";
import "../script/utils/TestDataLib.sol";
import "forge-std/console.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Base64} from "solady/utils/Base64.sol";
import {Measurement} from "../src/lib/LibTEE.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CVMRegistry} from "../src/usecases/CVMRegistry.sol";

contract CvmTest is TestSetup {
    
    CVMRegistry registry;
    using stdJson for string;

    function setUp() public override {
        super.setUp();

        vm.startBroadcast(owner);
        CVMRegistry registryImpl = new CVMRegistry(
            address(workloadVerifier)
        );

        bytes memory ownerInitData = abi.encodeWithSelector(
            CVMRegistry.initialize.selector, 
            owner
        );
        registry = CVMRegistry(address(new ERC1967Proxy(
            address(registryImpl),
            ownerInitData
        )));
        vm.stopBroadcast();

        console.log("CVMRegistry deployed at:", address(registry));
    }

    function testGcpTdxCvm() public {
        // pinned August 25th, 2025, 0945h UTC
        vm.warp(1756115100);
        TdxTestData memory testData = TestDataLib.loadTdxData(
            string.concat(vm.projectRoot(), "/test/testdata/cy/registration_gcp_tdx.json")
        );
        bytes memory googleCa = testData.tpmCerts[testData.tpmCerts.length - 1];
        vm.prank(owner);
        tpmAttestation.addCA(googleCa);

        // read the calldata from sample file
        string memory json = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/testdata/xh/gcp-tdx-registration.json"
            )
        );
        string memory encodedCalldata = json.readString(".calldata");
        bytes memory decodedCalldata = Base64.decode(encodedCalldata);

        (bool success, bytes memory result) = address(registry).call(decodedCalldata);
        assertTrue(success, string(result));

        bytes32 actualMeasurement = keccak256(result);

        string memory gmJson = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/testdata/xh/gcp-tdx-test-golden_measurements.json"
            )
        );
        string memory encodedGoldenMeasurements = gmJson.readString(".golden_measurement");
        bytes32 expectedMeasurement = bytes32(Base64.decode(encodedGoldenMeasurements));

        assertEq(expectedMeasurement, actualMeasurement);

        string memory reattestJson = vm.readFile(
            string.concat(
                vm.projectRoot(),
                "/test/testdata/xh/gcp-tdx-reattestation.json"
            )
        );
        string memory encodedReattestCalldata = reattestJson.readString(".calldata");
        bytes memory decodedReattestCalldata = Base64.decode(encodedReattestCalldata);

        (bool reattestSuccess, bytes memory reattestResult) = address(registry).call(decodedReattestCalldata);
        assertTrue(reattestSuccess, string(reattestResult));
    }
}