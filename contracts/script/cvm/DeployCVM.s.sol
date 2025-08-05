// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console} from "forge-std/console.sol";
import {DeploymentConfig} from "../utils/DeploymentConfig.sol";
import "../utils/Salt.sol";

import {CVMVerifier} from "../../src/usecases/CVMVerifier.sol";

contract DeployCVM is DeploymentConfig {
    address owner = vm.envAddress("OWNER");
    address workloadVerifier = readContractAddress("WorkloadVerifierProxy");

    modifier broadcast() {
        vm.startBroadcast(owner);
        _;
        vm.stopBroadcast();
    }

    function run() public broadcast {
        deployCvmVerifier();
    }

    function deployCvmVerifierImpl() public broadcast returns (address implAddress) {
        // deploy the CVMVerifier implementation
        CVMVerifier cvmVerifier = new CVMVerifier{salt: CVM_VERIFIER_IMPL_SALT}();
        implAddress = address(cvmVerifier);

        console.log("CVMVerifier implementation deployed at:", implAddress);

        // write the implementation address to JSON
        writeToJson("CVMVerifierImpl", implAddress);
    }

    function deployCvmVerifier() public broadcast {
        // deploy the CVMVerifier implementation
        address implAddress = deployCvmVerifierImpl();

        // deploy the CVMVerifier proxy
        ERC1967Proxy cvmVerifierProxy = new ERC1967Proxy{salt: CVM_VERIFIER_PROXY_SALT}(
            implAddress,
            abi.encodeWithSelector(CVMVerifier.initialize.selector, owner, workloadVerifier)
        );
        address proxyAddress = address(cvmVerifierProxy);

        console.log("CVMVerifier proxy deployed at:", proxyAddress);

        // write the proxy address to JSON
        writeToJson("CVMVerifierProxy", proxyAddress);
    }

    function upgradeCvmVerifier(address newImpl, bytes memory data) public broadcast {
        // Check if the proxy exists
        CVMVerifier cvmVerifierProxy = CVMVerifier(payable(readContractAddress("CVMVerifierProxy")));

        // deploy the new implementation
        if (newImpl == address(0)) {
            newImpl = deployCvmVerifierImpl();
        }

        // upgrade the proxy to the new implementation
        cvmVerifierProxy.upgradeToAndCall(newImpl, data);

        console.log("CVMVerifier upgraded to new implementation at:", newImpl);
    }
}