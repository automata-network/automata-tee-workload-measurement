<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>


# Automata TEE Workload Measurement
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Automata TPM Attestation](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)


This repository contains smart contracts for onchain verification and management of Confidential VM (CVM) workloads hosted on cloud service providers. It consists of two main components:

1. **TEE Workload Measurement** - Verifies the integrity and measurement of CVM workloads
2. **CVM Registry** - Manages CVM identities and their attestation lifecycle

## Table of Contents

- [Overview](#overview)
  - [Part 1: TEE Workload Measurement](#part-1-tee-workload-measurement)
  - [Part 2: CVM Registry](#part-2-cvm-registry)
- [Deployment Info](#deployment-info)
  - [Workload Verifier](#workload-verifier)
  - [CVM Registry](#cvm-registry-1)
- [Developer Documentation](#developer-documentation)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [Support](#support)

## Overview

Confidential VMs (CVMs) leverage Trusted Execution Environment (TEE) hardware—such as Intel TDX and AMD SEV-SNP—to protect code and data from tampering by the host OS and other VMs. Cloud service providers equip CVMs with virtual Trusted Platform Modules (TPMs) that cryptographically measure and attest to the integrity of the boot process and running workload.

This project currently supports CVMs with Intel TDX or AMD SEV-SNP on Azure and Google Cloud Platform (GCP), with full onchain verification implemented in Solidity for EVM networks.

Our goal is platform-agnostic coverage, and we are actively working to support additional TEE technologies, cloud providers, and Web3 ecosystems.

### Part 1: TEE Workload Measurement

The **Workload Verifier** contract provides cryptographic verification of CVM workload integrity by combining TEE attestation with TPM-based boot measurements. It ensures that code running in a CVM has not been tampered with and is executing on genuine TEE hardware.

**Key Features:**
- Verifies TEE attestation reports from Intel TDX and AMD SEV-SNP
- Validates TPM quotes and PCR measurements
- Ensures binding between TEE and TPM components
- Generates canonical measurement hashes (Golden Measurements)
- Multiple verification methods: onchain Solidity, ZK proofs (RiscZero, SP1)

**Use Cases:**
- Prove workload integrity before granting access to sensitive data

For detailed integration guide and API reference, see the [Developer Guide](./docs/DEVELOPER_GUIDE.md#workload-measurement-contract) and [contracts documentation](./README_CONTRACTS.md).

### Part 2: CVM Registry

The **CVM Registry** provides identity and lifecycle management for CVM workloads. It maps a CVM's identity to its attestation configuration, system and workload measurement hash, and freshness metadata.

**Key Features:**
- CVM Identity management for using CVM public key
- Attested CVM identity lifecycle tracking (registration, re-attestation, TTL management)
- Freshness enforcement via configurable TTL windows
- Identity rotation with attestation-based proof
- Replay protection using per-identity nonces
- Domain separation for secure message signing

**Key Capabilities:**
- **Registration**: Bootstrap CVM identity using attestation
- **Re-attestation**: Refresh TPM collateral while reusing TEE attestation, optionally update CVM identity
- **TTL Management**: Configure custom freshness windows for TEE and TPM
- **Key Rotation**: Securely rotate identity keys with attestation proof

**Use Cases:**
- Gate onchain actions based on verified CVM identity and liveness
- Track CVM workload states across their lifecycle
- Enable CVMs to sign authorized messages for downstream applications
- Implement access control based on CVM identity freshness

For detailed technical documentation, see the [Developer Guide](./docs/DEVELOPER_GUIDE.md#cvm-registry-contract) and [CVM Registry Primer](./docs/primer/cvm-registry-primer.md).

## Deployment Info

### Workload Verifier

| Network | Contract Address |
| --- | --- |
| Automata Testnet | [0xDb99cc64cb856EB388DAca7B89aee9e844f63aFd](https://explorer-testnet.ata.network/address/0xDb99cc64cb856EB388DAca7B89aee9e844f63aFd) |
| Sepolia Testnet | [0xa6DF41BCe5cA0352042E5a53f33c9C9226AD2119](https://sepolia.etherscan.io/address/0xa6DF41BCe5cA0352042E5a53f33c9C9226AD2119) |

### CVM Registry

| Network | Contract Address |
| --- | --- |
| Automata Testnet | [0x262eAcF7DC665a6dc416AdDB45a4dB5F1e79aF38](https://explorer-testnet.ata.network/address/0x262eAcF7DC665a6dc416AdDB45a4dB5F1e79aF38) |
| Sepolia Testnet | [0xE626f5503B455F775AA9845843B46033a26A635d](https://sepolia.etherscan.io/address/0xE626f5503B455F775AA9845843B46033a26A635d) |


## Related Projects

- [DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation) - On-chain verification of Intel SGX/TDX DCAP attestations
- [TDX Attestation SDK](https://github.com/automata-network/tdx-attestation-sdk) - TDX Development SDK to generate Intel TDX quotes from cloud providers.
- [AMD SEV-SNP Attestation SDK](https://github.com/automata-network/amd-sev-snp-attestation-sdk) - On-chain verification of AMD SEV-SNP attestations
- [AWS Nitro Enclave Attestation](https://github.com/automata-network/aws-nitro-enclave-attestation) - On-chain verification of AWS Nitro Enclave attestations
- [TPM Attestation](https://github.com/automata-network/automata-tpm-attestation) - On-chain verification of TPM Quote and TPM certificates management
- [CVM Base Image](https://github.com/automata-network/cvm-base-image) - Tools for deploying Confidential VMs with workloads on GCP, AWS, and Azure


## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For questions and support, please open an issue.