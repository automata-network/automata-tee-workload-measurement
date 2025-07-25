// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {console} from "forge-std/console.sol";
import {P256Configuration} from "./utils/P256Configuration.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import "./utils/Salt.sol";

import {CertChainRegistry} from "../src/CertChainRegistry.sol";
import {WorkloadVerifier} from "../src/WorkloadVerifier.sol";

contract Deploy is DeploymentConfig, P256Configuration {
    address owner = vm.envAddress("OWNER");
    address dcapAttestationAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
    address snpAttestationAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
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
        deployCertchainRegistry();
        deployWorkloadVerifier(false); // Set allowMockAttestation to false by default
    }

    function deployCertchainRegistryImpl() public broadcast returns (address implAddress) {
        // deploy the CertChainRegistry implementation
        CertChainRegistry certchainRegistry = new CertChainRegistry{salt: CERT_CHAIN_REGISTRY_IMPL_SALT}();
        implAddress = address(certchainRegistry);

        console.log("CertChainRegistry implementation deployed at:", implAddress);

        // write the implementation address to JSON
        writeToJson("CertChainRegistryImpl", implAddress);
    }

    function deployWorkloadVerifierImpl() public broadcast returns (address implAddress) {
        // deploy the WorkloadVerifier implementation
        WorkloadVerifier workloadVerifier = new WorkloadVerifier{salt: WORKLOAD_VERIFIER_IMPL_SALT}();
        implAddress = address(workloadVerifier);

        console.log("WorkloadVerifier implementation deployed at:", implAddress);

        // write the implementation address to JSON
        writeToJson("WorkloadVerifierImpl", implAddress);
    }

    function deployCertchainRegistry() public broadcast {
        // deploy the CertChainRegistry implementation
        address implAddress = deployCertchainRegistryImpl();

        // deploy the CertChainRegistry proxy
        ERC1967Proxy certchainRegistryProxy = new ERC1967Proxy(
            implAddress, abi.encodeWithSelector(CertChainRegistry.initialize.selector, owner, simulateVerify())
        );
        address proxyAddress = address(certchainRegistryProxy);
        console.log("CertChainRegistry proxy deployed at:", proxyAddress);

        // write the proxy address to JSON
        writeToJson("CertChainRegistryProxy", proxyAddress);
    }

    function deployWorkloadVerifier(bool allowMockAttestation) public broadcast {
        // deploy the WorkloadVerifier implementation
        address implAddress = deployWorkloadVerifierImpl();

        // deploy the WorkloadVerifier proxy
        ERC1967Proxy workloadVerifierProxy = new ERC1967Proxy(
            implAddress,
            abi.encodeWithSelector(
                WorkloadVerifier.initialize.selector,
                owner,
                dcapAttestationAddr,
                snpAttestationAddr,
                readContractAddress("CertChainRegistryProxy"),
                allowMockAttestation
            )
        );
        address proxyAddress = address(workloadVerifierProxy);
        console.log("WorkloadVerifier proxy deployed at:", proxyAddress);

        // write the proxy address to JSON
        writeToJson("WorkloadVerifierProxy", proxyAddress);
    }

    function upgradeCertchainRegistry(address newImpl, bytes calldata data) public broadcast {
        // First, check if the certchain registry proxy already exists
        CertChainRegistry certchainRegistryProxy =
            CertChainRegistry(payable(readContractAddress("CertChainRegistryProxy")));

        if (newImpl == address(0)) {
            // Deploy the new implementation
            newImpl = deployCertchainRegistryImpl();
        }

        // Upgrade the proxy to the new implementation
        certchainRegistryProxy.upgradeToAndCall(newImpl, data);
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
