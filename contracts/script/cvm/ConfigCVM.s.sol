// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {console} from "forge-std/console.sol";
import {DeploymentConfig} from "../utils/DeploymentConfig.sol";
import {TestDataLib, stdJson} from "../utils/TestDataLib.sol";
import {TEEType, GoldenMeasurement} from "../../src/lib/LibTEE.sol";

import {CVMVerifier} from "../../src/usecases/CVMVerifier.sol";

contract ConfigCVM is DeploymentConfig {

    using stdJson for string;

    address owner = vm.envAddress("OWNER");
    string constant GOLDEN_MEASUREMENT_KEY = ".golden_measurement";
    string TDX_KEY = string.concat(GOLDEN_MEASUREMENT_KEY, ".tdx");
    string SNP_KEY = string.concat(GOLDEN_MEASUREMENT_KEY, ".snp");

    modifier broadcast() {
        vm.startBroadcast(owner);
        _;
        vm.stopBroadcast();
    }

    function registerGm(string memory gmPath) public broadcast {
        address cvmVerifier = readContractAddress("CVMVerifierProxy");
        (GoldenMeasurement memory goldenMeasurement,) = readGmJson(gmPath);

        // Register the golden measurement in the CVMVerifier contract
        CVMVerifier(cvmVerifier).registerGm(
            goldenMeasurement
        );
    }

    function readGmJson(string memory gmPath) public view returns (
        GoldenMeasurement memory goldenMeasurement,
        bytes32 gmHash
    ) {
        string memory gmJson = vm.readFile(gmPath);

        TEEType teeType;
        if (gmJson.keyExists(TDX_KEY)) {
            teeType = TEEType.IntelTDX;
        } else if (gmJson.keyExists(SNP_KEY)) {
            teeType = TEEType.AmdSevSnp;
        } else {
            revert("Invalid JSON or unsupported TEE type in golden measurement");
        }

        console.log("Parsing Golden Measurement for TEE type:", uint(teeType));

        if (teeType == TEEType.IntelTDX) {
            goldenMeasurement = TestDataLib.getTdxGoldenMeasurement(
                TestDataLib.parseTdxGoldenMeasurement(gmJson, GOLDEN_MEASUREMENT_KEY)
            );
        } else if (teeType == TEEType.AmdSevSnp) {
            goldenMeasurement = TestDataLib.getSnpGoldenMeasurement(
                TestDataLib.parseSnpGoldenMeasurement(gmJson, GOLDEN_MEASUREMENT_KEY)
            );
        }

        gmHash = keccak256(abi.encode(goldenMeasurement));
        console.log("Golden Measurement hash:");
        console.logBytes32(gmHash);
    }
}