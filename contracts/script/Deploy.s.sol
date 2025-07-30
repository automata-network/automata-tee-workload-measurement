// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console} from "forge-std/console.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {WorkloadVerifier} from "../src/WorkloadVerifier.sol";

import "./utils/Salt.sol";

contract Deploy is DeploymentConfig {
    address owner = vm.envAddress("OWNER");
    address dcapAttestationAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
    address snpAttestationAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
    address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
    bool locked = false;

    modifier broadcast() {
        if (!locked) {
            locked = true;
            vm.startBroadcast(owner);
            _;
            vm.stopBroadcast();
            locked = false;
        }
    }

    function run() public broadcast {
        deployWorkloadVerifier(false); // Set allowMockAttestation to false by default
    }

    function deployWorkloadVerifierImpl() public broadcast returns (address implAddress) {
        // deploy the WorkloadVerifier implementation
        WorkloadVerifier workloadVerifier = new WorkloadVerifier{salt: WORKLOAD_VERIFIER_IMPL_SALT}();
        implAddress = address(workloadVerifier);

        console.log("WorkloadVerifier implementation deployed at:", implAddress);

        // write the implementation address to JSON
        writeToJson("WorkloadVerifierImpl", implAddress);
    }

    function deployWorkloadVerifier(bool allowMockAttestation) public broadcast {
        // deploy the WorkloadVerifier implementation
        address implAddress = deployWorkloadVerifierImpl();

        // deploy the WorkloadVerifier proxy
        ERC1967Proxy workloadVerifierProxy = new ERC1967Proxy{salt: WORKLOAD_VERIFIER_PROXY_SALT}(
            implAddress,
            abi.encodeWithSelector(
                WorkloadVerifier.initialize.selector,
                owner,
                dcapAttestationAddr,
                snpAttestationAddr,
                tpmAttestationAddr,
                allowMockAttestation
            )
        );
        address proxyAddress = address(workloadVerifierProxy);
        console.log("WorkloadVerifier proxy deployed at:", proxyAddress);

        // write the proxy address to JSON
        writeToJson("WorkloadVerifierProxy", proxyAddress);
    }

    function upgradeWorkloadVerifier(address newImpl, bytes calldata data) public broadcast {
        // First, check if the workload verifier proxy already exists
        WorkloadVerifier workloadVerifierProxy = WorkloadVerifier(payable(readContractAddress("WorkloadVerifierProxy")));

        if (newImpl == address(0)) {
            // Deploy the new implementation
            newImpl = deployWorkloadVerifierImpl();
        }

        // Upgrade the proxy to the new implementation
        workloadVerifierProxy.upgradeToAndCall(newImpl, data);
    }
}
