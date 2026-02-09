// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";

import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

/// @title DeployProd
/// @notice Deploys all contracts using existing Automata attestation contracts
/// @dev Requires environment variables to be set (see .env.example):
///      - DCAP_ATTESTATION_ADDR: Automata DCAP attestation contract address
///      - SNP_ATTESTATION_ADDR: Automata SNP attestation contract address
///      - TPM_ATTESTATION_ADDR: Automata TPM attestation contract address
///      - P256_VERIFIER: (Optional) P256 verifier address. If not set, auto-detects EIP-7212 precompile
///      - PRIVATE_KEY: Deployer private key
///
/// Usage:
///      source .env
///      forge script script/DeployProd.s.sol:DeployProd --rpc-url $RPC_URL --broadcast --verify
contract DeployProd is DeployBase {
    /// @dev EIP-7212 P256 precompile address (Osaka/Prague+)
    address constant P256_PRECOMPILE = 0x0000000000000000000000000000000000000100;

    function run() external {
        // Load configuration from environment
        address dcapAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
        address snpAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
        address tpmAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
        // P256_VERIFIER is optional - if not set, will auto-detect
        address p256Addr = vm.envOr("P256_VERIFIER", address(0));
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        address deployer = vm.addr(deployerPrivateKey);

        console.log("=== Production Deployment Mode ===");
        console.log("Deployer:", deployer);
        console.log("");
        console.log("External Dependencies:");
        console.log("  DCAP Attestation:", dcapAddr);
        console.log("  SNP Attestation:", snpAddr);
        console.log("  TPM Attestation:", tpmAddr);

        // Validate external contracts exist
        require(dcapAddr.code.length > 0, "DCAP Attestation contract not found");
        require(snpAddr.code.length > 0, "SNP Attestation contract not found");
        require(tpmAddr.code.length > 0, "TPM Attestation contract not found");

        // Resolve P256 verifier
        if (p256Addr == address(0)) {
            p256Addr = _resolveP256Verifier();
        } else {
            require(p256Addr.code.length > 0, "P256 Verifier contract not found");
            console.log("  P256 Verifier (configured):", p256Addr);
        }
        console.log("");

        // Set external dependencies
        dcapAttestation = IDcapAttestation(dcapAddr);
        snpAttestation = ISnpAttestation(snpAddr);
        tpmAttestation = ITpmAttestation(tpmAddr);
        p256Verifier = p256Addr;

        vm.startBroadcast(deployerPrivateKey);

        // Deploy main contracts
        _deployAll();

        vm.stopBroadcast();
    }

    /// @dev Auto-detect P256 verifier: prefer EIP-7212 precompile if available
    function _resolveP256Verifier() internal view returns (address) {
        if (_isP256PrecompileAvailable()) {
            console.log("  P256 Verifier (EIP-7212 precompile):", P256_PRECOMPILE);
            return P256_PRECOMPILE;
        }
        revert("P256_VERIFIER not set and EIP-7212 precompile not available");
    }

    /// @dev Check if EIP-7212 P256 precompile is functional
    function _isP256PrecompileAvailable() internal view returns (bool) {
        // Test vector from EIP-7212: hash || r || s || x || y (160 bytes)
        bytes memory testInput = hex"4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e";

        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(testInput);

        if (success && result.length == 32) {
            uint256 valid = abi.decode(result, (uint256));
            return valid == 1;
        }
        return false;
    }
}

/// @title DeployProdAnvil
/// @notice Fork mode deployment - forks mainnet/testnet and deploys on top
/// @dev Usage:
///      source .env
///      forge script script/DeployProd.s.sol:DeployProdAnvil --rpc-url $RPC_URL --broadcast
contract DeployProdAnvil is DeployBase {
    function run() external {
        // Load configuration from environment
        address dcapAddr = vm.envAddress("DCAP_ATTESTATION_ADDR");
        address snpAddr = vm.envAddress("SNP_ATTESTATION_ADDR");
        address tpmAddr = vm.envAddress("TPM_ATTESTATION_ADDR");
        address p256Addr = vm.envAddress("P256_VERIFIER");

        // Use default anvil private key if not set
        uint256 deployerPrivateKey = vm.envOr(
            "PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
        );

        address deployer = vm.addr(deployerPrivateKey);

        console.log("=== Production Anvil Fork Mode ===");
        console.log("Deployer:", deployer);
        console.log("");
        console.log("External Dependencies:");
        console.log("  DCAP Attestation:", dcapAddr);
        console.log("  SNP Attestation:", snpAddr);
        console.log("  TPM Attestation:", tpmAddr);
        console.log("  P256 Verifier:", p256Addr);
        console.log("");

        // Set external dependencies (don't validate code in fork mode, contracts may be on forked chain)
        dcapAttestation = IDcapAttestation(dcapAddr);
        snpAttestation = ISnpAttestation(snpAddr);
        tpmAttestation = ITpmAttestation(tpmAddr);
        p256Verifier = p256Addr;

        vm.startBroadcast(deployerPrivateKey);

        // Deploy main contracts
        _deployAll();

        vm.stopBroadcast();
    }
}
