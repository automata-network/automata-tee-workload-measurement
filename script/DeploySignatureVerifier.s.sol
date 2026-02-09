// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {P256Configuration} from "./utils/P256Config.sol";
import {SIGNATURE_VERIFIER_SALT} from "./utils/Salt.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import "forge-std/console.sol";

contract DeploySignatureVerifier is DeploymentConfig, P256Configuration {
    function run() public override {
        // Detect P256 verifier address BEFORE starting broadcast
        // simulateVerify() uses FFI (cast call) which cannot run inside broadcast
        address p256Verifier = simulateVerify();

        // Start broadcast with OWNER from environment
        vm.startBroadcast(vm.envAddress("OWNER"));

        // Deploy SignatureVerifier with CREATE2
        SignatureVerifier signatureVerifier = new SignatureVerifier{salt: SIGNATURE_VERIFIER_SALT}(p256Verifier);

        console.log("SignatureVerifier deployed at:", address(signatureVerifier));

        vm.stopBroadcast();

        // Persist deployment address to JSON
        writeToJson("SignatureVerifier", address(signatureVerifier));
    }
}
