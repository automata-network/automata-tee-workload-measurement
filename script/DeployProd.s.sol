// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {P256Configuration} from "./utils/P256Config.sol";
import {
    SIGNATURE_VERIFIER_SALT,
    TEE_VERIFIER_SALT,
    BASE_IMAGE_REGISTRY_IMPL_SALT,
    BASE_IMAGE_REGISTRY_PROXY_SALT,
    WORKLOAD_REGISTRY_IMPL_SALT,
    WORKLOAD_REGISTRY_PROXY_SALT,
    KEY_RESOLVER_IMPL_SALT,
    KEY_RESOLVER_PROXY_SALT,
    SESSION_REGISTRY_IMPL_SALT,
    SESSION_REGISTRY_PROXY_SALT
} from "./utils/Salt.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {KeyResolver} from "../src/KeyResolver.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployProd
/// @notice Deploys all contracts using existing Automata attestation contracts
/// @dev Requires environment variables:
///      - DCAP_ATTESTATION_ADDR: Automata DCAP attestation contract address
///      - SNP_ATTESTATION_ADDR: Automata SNP attestation contract address
///      - TPM_ATTESTATION_ADDR: Automata TPM attestation contract address
///      - PRIVATE_KEY: Deployer private key (also used as initial owner)
///
/// Usage:
///      source .env
///      forge script script/DeployProd.s.sol:DeployProd --rpc-url $RPC_URL --broadcast --verify
contract DeployProd is DeploymentConfig, P256Configuration {
    function run() public override {
        // Load configuration from environment
        address dcapAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
        address snpAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
        address tpmAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
        // uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.envAddress("OWNER");

        console.log("=== Production Deployment ===");
        console.log("Deployer / Owner:", deployer);
        console.log("");
        console.log("External Dependencies:");
        console.log("  DCAP Attestation:", dcapAddr);
        console.log("  SNP Attestation:", snpAddr);
        console.log("  TPM Attestation:", tpmAddr);

        // Validate external contracts exist
        require(dcapAddr.code.length > 0, "DCAP Attestation contract not found");
        require(snpAddr.code.length > 0, "SNP Attestation contract not found");
        require(tpmAddr.code.length > 0, "TPM Attestation contract not found");

        // Resolve P256 verifier (uses FFI, must run before broadcast)
        address p256Verifier = simulateVerify();
        console.log("");

        vm.startBroadcast(deployer);

        // 1. SignatureVerifier (no proxy)
        SignatureVerifier signatureVerifier = new SignatureVerifier{salt: SIGNATURE_VERIFIER_SALT}(p256Verifier);
        console.log("SignatureVerifier:", address(signatureVerifier));

        // 2. TeeVerifier (no proxy)
        TeeVerifier teeVerifier =
            new TeeVerifier{salt: TEE_VERIFIER_SALT}(IDcapAttestation(dcapAddr), ISnpAttestation(snpAddr));
        console.log("TeeVerifier:", address(teeVerifier));

        // 3. BaseImageRegistry (impl + proxy)
        BaseImageRegistry birImpl = new BaseImageRegistry{salt: BASE_IMAGE_REGISTRY_IMPL_SALT}(signatureVerifier);
        ERC1967Proxy birProxy = new ERC1967Proxy{salt: BASE_IMAGE_REGISTRY_PROXY_SALT}(
            address(birImpl), abi.encodeCall(BaseImageRegistry.initialize, (deployer))
        );
        console.log("BaseImageRegistry:", address(birProxy));

        // 4. WorkloadRegistry (impl + proxy)
        WorkloadRegistry wrImpl = new WorkloadRegistry{salt: WORKLOAD_REGISTRY_IMPL_SALT}(signatureVerifier);
        ERC1967Proxy wrProxy = new ERC1967Proxy{salt: WORKLOAD_REGISTRY_PROXY_SALT}(
            address(wrImpl), abi.encodeCall(WorkloadRegistry.initialize, (deployer))
        );
        console.log("WorkloadRegistry:", address(wrProxy));

        // 5. KeyResolver (impl + proxy)
        KeyResolver krImpl = new KeyResolver{salt: KEY_RESOLVER_IMPL_SALT}();
        ERC1967Proxy krProxy = new ERC1967Proxy{salt: KEY_RESOLVER_PROXY_SALT}(
            address(krImpl), abi.encodeCall(KeyResolver.initialize, (deployer))
        );
        console.log("KeyResolver:", address(krProxy));

        // 6. SessionRegistry (impl + proxy)
        SessionRegistry srImpl = new SessionRegistry{salt: SESSION_REGISTRY_IMPL_SALT}(
            teeVerifier,
            ITpmAttestation(tpmAddr),
            signatureVerifier,
            BaseImageRegistry(address(birProxy)),
            WorkloadRegistry(address(wrProxy))
        );
        ERC1967Proxy srProxy = new ERC1967Proxy{salt: SESSION_REGISTRY_PROXY_SALT}(
            address(srImpl), abi.encodeCall(SessionRegistry.initialize, (deployer))
        );
        console.log("SessionRegistry:", address(srProxy));

        vm.stopBroadcast();

        // Persist all canonical (proxy) addresses to JSON
        writeToJson("SignatureVerifier", address(signatureVerifier));
        writeToJson("TeeVerifier", address(teeVerifier));
        writeToJson("BaseImageRegistry", address(birProxy));
        writeToJson("WorkloadRegistry", address(wrProxy));
        writeToJson("KeyResolver", address(krProxy));
        writeToJson("SessionRegistry", address(srProxy));

        console.log("");
        console.log("=== Deployment Complete ===");
    }
}
