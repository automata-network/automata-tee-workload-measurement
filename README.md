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


This repo contains the onchain program (smart contracts) for verifying the integrity and measurement of a Confidential VM (CVM) workload hosted on cloud service providers.

Code and data in CVMs are protected from tampering by the host OS (and other CVMs) with TEE hardware, such as Intel TDX and AMD SEV-SNP. Cloud service providers generally also equip CVMs with virtual TPM, to cryptographically store measurements of the boot process, ensuring integrity of the CVM image.

Currently, the Workload verifier contract supports users who provisioned their CVMs equiped with Intel TDX or AMD-SEV-SNP, running on either Azure or Google Cloud Platform (GCP). The full workflow has been implemented in Solidity for EVM network. Click [here](./contracts/README.md) to learn more.

Ideally, the goal of this project is to be platform agnostic, covering as wide range of users as possible. We strive to continue to work diligently to support more TEEs, cloud providers and Web3 ecosystems.

## Table of Contents

- [Overview](#overview)
- [Deployment Info](#deployment-info)
  - [Workload Verifier](#workload-verifier)
  - [CVM Registry](#cvm-registry)
- [Related Projects](#related-projects)
- [Contributing](#contributing)
- [Support](#support)

## Overview

```mermaid
sequenceDiagram
    participant A as Application Contracts
    participant W as Workload Verifier
    participant TEE as TEE Onchain Attestation
    participant TPM as TPM Attestation

    A->>W: 1. TEE Attestation Report, Workload Collateral
    W->>TEE: 2. TEE Attestation Report
    TEE-->>W: TEE Verification Status and Output
    W->>TPM: 3. Workload Collateral
    opt GCP
        TPM-->>TPM: Extracts and verifies the AK Pubkey from a list of trusted CAs
    end
    TPM->>TPM: 4. Checks PCR Digest
    TPM-->>W: TPM quote has been successfully verified and returns `extraData` value to the caller.
    W->>W: 5. Verifies the report ID to check binding between TEE and TPM
    W->>W: 6. Generates the measurement structure, encapsulating the TEE Report content and measured PCR values.
    W->>A: 7. Returns the hash of the measurement and TPM `extraData` value.

```

1. The application submits the TEE Attestation Report, and the workload collateral to the `WorkloadVerifier.sol` contract. Workload collateral is a collection of data, consisting the TPM quote, TPM Signature, TPM Attestation Key (or AK certificate chain) and an array of PCR measurement.

2. TEE Attestation Report verification shows that the CVM is running in a TEE provided by genuine hardware.
    
    > a. If the CVM were hosted on Azure, this step also ensures that the report data must contain the hash of the TPM Attestation Key.

3. The TPM quote and signature are verified against the provided TPM Attestation Key.
    
    > a. If TPM Attestation Key were not checked in *step 2(a)*, the key is extracted from the leaf of the AK Certificate Chain, which must be checked for valid root of trust.

4. The list of PCR indices provided in the collateral must match with the PCR selection bitmap in the TPM quote; the hash chain of PCR measurement values yields a value that must match the PCR digest value in the TPM quote.

5. The provided Report ID must be found in both TEE Attestation Report and PCR 16 of the TPM. This step indicates the binding between TEE and TPM.
    
    > a. The only exception to this rule applies to Azure TDX CVM. As stated in *2(a)*, the report data provides us with information about the AK that signs the TPM quote, which is already verified in *step 3*.

6. Generates the `Measurement` object. A data structure containing the content of the TEE Report and an array of measured PCRs. Each PCR may contain a deterministic PCR value and/or a list of event logs that the workload produces.

    > a. External contracts may retrieve the Golden Measurement instead of the hash, if developers intend to perform additional checks on the measurement values.

7. Optionally, computes the measurement hash, which is a holistic representation of the state of the CVM. Application developers can provide a reference measurement as a policy that CVM workloads must comply, also known as the **Golden Measurement** value. Developers should also check for the correctness of TPM `extraData` value.

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