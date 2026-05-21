// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {SESSION_REGISTRY_IMPL_SALT, SESSION_REGISTRY_PROXY_SALT} from "./utils/Salt.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from "../src/interfaces/registries/IWorkloadRegistry.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "forge-std/console.sol";

contract DeploySessionRegistry is DeploymentConfig {
    function _deploySessionRegistryImpl() internal returns (address) {
        address teeVerifierAddr = readContractAddress("TeeVerifier");
        address signatureVerifierAddr = readContractAddress("SignatureVerifier");
        address akCollateralVerifierAddr = readContractAddress("AkCollateralVerifier");
        address baseImageRegistryAddr = readContractAddress("BaseImageRegistry");
        address workloadRegistryAddr = readContractAddress("WorkloadRegistry");
        address tpmAttestationAddr = vm.envAddress("TPM_ATTESTATION_ADDR");

        console.log("Using TeeVerifier at:", teeVerifierAddr);
        console.log("Using SignatureVerifier at:", signatureVerifierAddr);
        console.log("Using AkCollateralVerifier at:", akCollateralVerifierAddr);
        console.log("Using BaseImageRegistry at:", baseImageRegistryAddr);
        console.log("Using WorkloadRegistry at:", workloadRegistryAddr);
        console.log("Using TPM attestation at:", tpmAttestationAddr);

        SessionRegistry impl = new SessionRegistry{salt: SESSION_REGISTRY_IMPL_SALT}(
            ITeeVerifier(teeVerifierAddr),
            ITpmAttestation(tpmAttestationAddr),
            ISignatureVerifier(signatureVerifierAddr),
            IAkCollateralVerifier(akCollateralVerifierAddr),
            IBaseImageRegistry(baseImageRegistryAddr),
            IWorkloadRegistry(workloadRegistryAddr)
        );
        console.log("SessionRegistry implementation deployed at:", address(impl));
        writeToJson("SessionRegistryImpl", address(impl));
        return address(impl);
    }

    function _deploySessionRegistryProxy(address impl) internal returns (address) {
        if (impl == address(0)) {
            impl = _deploySessionRegistryImpl();
        }

        address owner = vm.envAddress("OWNER");
        bytes memory initData = abi.encodeCall(SessionRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy{salt: SESSION_REGISTRY_PROXY_SALT}(impl, initData);
        console.log("SessionRegistry proxy deployed at:", address(proxy));
        writeToJson("SessionRegistry", address(proxy));
        return address(proxy);
    }

    function _upgradeSessionRegistry(address impl, bytes memory data) internal {
        if (impl == address(0)) {
            impl = _deploySessionRegistryImpl();
        }

        address proxy = readContractAddress("SessionRegistry");
        UUPSUpgradeable(proxy).upgradeToAndCall(impl, data);
        writeToJson("SessionRegistryImpl", impl);
    }

    function deploySessionRegistryImpl() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deploySessionRegistryImpl();
        vm.stopBroadcast();
    }

    function deploySessionRegistryProxy(address impl) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deploySessionRegistryProxy(impl);
        vm.stopBroadcast();
    }

    function upgradeSessionRegistry(address impl, bytes memory data) public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _upgradeSessionRegistry(impl, data);
        vm.stopBroadcast();
    }

    function run() public virtual {
        deploySessionRegistryProxy(address(0));
    }
}
