// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import "forge-std/console.sol";
import {TestSetup} from "./utils/TestSetup.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Base64} from "solady/utils/Base64.sol";
import {Measurement} from "../src/lib/LibTEE.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CVMRegistry, CVMConfig} from "../src/usecases/CVMRegistry.sol";

contract CvmAzureTest is TestSetup {
    CVMRegistry registry;

    using stdJson for string;

    function setUp() public override {
        super.setUp();

        vm.startBroadcast(owner);
        CVMRegistry registryImpl = new CVMRegistry(address(workloadVerifier));

        bytes memory ownerInitData = abi.encodeWithSelector(CVMRegistry.initialize.selector, owner, P256_VERIFIER);
        registry = CVMRegistry(address(new ERC1967Proxy(address(registryImpl), ownerInitData)));
        vm.stopBroadcast();
    }

    function testAzureTdxCvm() public {
        // read the calldata from sample file
        string memory json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/tdx/azure-tdx-registration.json"));
        string memory encodedCalldata = json.readString(".calldata");
        bytes memory decodedCalldata = Base64.decode(encodedCalldata);

        (bool success, bytes memory result) = address(registry).call(decodedCalldata);
        assertTrue(success, string(result));

        bytes32 actualMeasurement = keccak256(result);

        string memory gmJson = vm.readFile(
            string.concat(vm.projectRoot(), "/test/testdata/azure/tdx/azure-tdx-test-golden_measurements.json")
        );
        string memory encodedGoldenMeasurements = gmJson.readString(".golden_measurement");
        bytes32 expectedMeasurement = bytes32(Base64.decode(encodedGoldenMeasurements));

        assertEq(expectedMeasurement, actualMeasurement);

        string memory reattestJson =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/tdx/azure-tdx-reattestation.json"));
        string memory encodedReattestCalldata = reattestJson.readString(".calldata");
        bytes memory decodedReattestCalldata = Base64.decode(encodedReattestCalldata);

        (bool reattestSuccess, bytes memory reattestResult) = address(registry).call(decodedReattestCalldata);
        assertTrue(reattestSuccess, string(reattestResult));

        bytes32 cvnIdentityHash = 0x49d4d52dca8f14b058e0521248f65c8b77557ae4bbb2fb2057d68eecc9ab3dc3;
        CVMConfig memory config = registry.getCvmConfig(cvnIdentityHash);

        uint64 teeTTLBefore = config.teeTTL;
        uint64 tpmTTLBefore = config.tpmTTL;

        string memory ttlUpdateJson =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/tdx/azure-tdx-update-ttl.json"));
        string memory encodedTtlUpdateCalldata = ttlUpdateJson.readString(".calldata");
        bytes memory decodedTtlUpdateCalldata = Base64.decode(encodedTtlUpdateCalldata);

        (bool ttlUpdateSuccess,) = address(registry).call(decodedTtlUpdateCalldata);
        assertTrue(ttlUpdateSuccess, "TTL update failed");

        CVMConfig memory updatedConfig = registry.getCvmConfig(cvnIdentityHash);
        assertNotEq(updatedConfig.teeTTL, teeTTLBefore, "TEE TTL not updated");
        assertNotEq(updatedConfig.tpmTTL, tpmTTLBefore, "TPM TTL not updated");
    }

    function testAzureSevSnp() public {
        // read the calldata from sample file
        string memory json =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/snp/azure-snp-registration.json"));
        string memory encodedCalldata = json.readString(".calldata");
        bytes memory decodedCalldata = Base64.decode(encodedCalldata);

        (bool success, bytes memory result) = address(registry).call(decodedCalldata);
        assertTrue(success, string(result));

        bytes32 actualMeasurement = keccak256(result);

        string memory gmJson = vm.readFile(
            string.concat(vm.projectRoot(), "/test/testdata/azure/snp/azure-snp-test-golden_measurements.json")
        );
        string memory encodedGoldenMeasurements = gmJson.readString(".golden_measurement");
        bytes32 expectedMeasurement = bytes32(Base64.decode(encodedGoldenMeasurements));

        assertEq(expectedMeasurement, actualMeasurement);

        string memory reattestJson =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/snp/azure-snp-reattestation.json"));
        string memory encodedReattestCalldata = reattestJson.readString(".calldata");
        bytes memory decodedReattestCalldata = Base64.decode(encodedReattestCalldata);

        (bool reattestSuccess, bytes memory reattestResult) = address(registry).call(decodedReattestCalldata);
        assertTrue(reattestSuccess, string(reattestResult));

        bytes32 cvnIdentityHash = 0xaa20254939b9e46d9120f828c6d45978255f6600a9c0a62b438643cb3ca2d5cd;
        CVMConfig memory config = registry.getCvmConfig(cvnIdentityHash);

        uint64 teeTTLBefore = config.teeTTL;
        uint64 tpmTTLBefore = config.tpmTTL;

        string memory ttlUpdateJson =
            vm.readFile(string.concat(vm.projectRoot(), "/test/testdata/azure/snp/azure-snp-update-ttl.json"));
        string memory encodedTtlUpdateCalldata = ttlUpdateJson.readString(".calldata");
        bytes memory decodedTtlUpdateCalldata = Base64.decode(encodedTtlUpdateCalldata);

        (bool ttlUpdateSuccess,) = address(registry).call(decodedTtlUpdateCalldata);
        assertTrue(ttlUpdateSuccess, "TTL update failed");

        CVMConfig memory updatedConfig = registry.getCvmConfig(cvnIdentityHash);
        assertNotEq(updatedConfig.teeTTL, teeTTLBefore, "TEE TTL not updated");
        assertNotEq(updatedConfig.tpmTTL, tpmTTLBefore, "TPM TTL not updated");
    }
}
