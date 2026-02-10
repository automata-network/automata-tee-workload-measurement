// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {P256Configuration} from "./utils/P256Config.sol";
import {SIGNATURE_VERIFIER_SALT} from "./utils/Salt.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import "forge-std/console.sol";

contract DeploySignatureVerifier is DeploymentConfig, P256Configuration {
    function _deploySignatureVerifier(address p256Verifier) internal returns (address) {
        SignatureVerifier signatureVerifier = new SignatureVerifier{salt: SIGNATURE_VERIFIER_SALT}(p256Verifier);
        console.log("SignatureVerifier deployed at:", address(signatureVerifier));
        writeToJson("SignatureVerifier", address(signatureVerifier));
        return address(signatureVerifier);
    }

    function deploySignatureVerifier() public virtual {
        address p256Verifier = simulateVerify();

        vm.startBroadcast(vm.envAddress("OWNER"));
        _deploySignatureVerifier(p256Verifier);
        vm.stopBroadcast();
    }

    function run() public virtual override {
        deploySignatureVerifier();
    }
}
