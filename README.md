<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata TEE Workload Measurement

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

On-chain verification and management of Confidential VM (CVM) workloads. The system establishes cryptographic chains of trust from TEE hardware (Intel TDX, AMD SEV-SNP) and virtual TPMs to on-chain verifiable session identities, enabling downstream smart contracts to authenticate messages from verified CVM workloads.

## Architecture

The system uses a three-tier registry to separate platform, application, and runtime concerns:

```
SessionRegistry (orchestrator — 9-step attestation verification)
├── BaseImageRegistry (OS/platform policies — PCR 0-19)
│   ├── BaseImage (name, version, URI)
│   ├── PlatformProfile (cloud + TEE config, invariant PCRs, platform attributes)
│   └── MeasurementVariant (machine-type PCR overrides, machine attributes)
├── WorkloadRegistry (application policies — PCR 20-23)
│   └── WorkloadSpec (container measurements, attribute requirements, base image access control)
├── TeeVerifier (dispatches to DCAP/SNP attestation verifiers; supports ZK backends)
├── SignatureVerifier (RS256, ES256, ES256K)
└── KeyResolver (public key fingerprint → PublicIdentity directory)
```

**Key Principles:**
- **Separation of Concerns** — Base images (privileged OS), workloads (unprivileged apps), and sessions (runtime identity) are managed independently
- **PublicIdentity Ownership** — Registry ownership is based on cryptographic keys, independent of EVM addresses
- **Immutable Verifiers** — `TeeVerifier` and `SignatureVerifier` are stateless and reusable across registries
- **Upgradeable Registries** — `BaseImageRegistry`, `WorkloadRegistry`, and `SessionRegistry` use UUPS proxies

## Project Structure

```
src/
├── SessionRegistry.sol           # Session orchestrator (9-step attestation verification)
├── BaseImageRegistry.sol         # OS/platform measurement policy management
├── WorkloadRegistry.sol          # Application measurement policy management
├── TeeVerifier.sol               # TEE attestation dispatcher (DCAP / SNP / ZK)
├── SignatureVerifier.sol          # Cryptographic signature verification (RS256, ES256, ES256K)
├── KeyResolver.sol               # Public key fingerprint directory
├── bases/                        # Base verification contracts
│   ├── TpmVerifier.sol           #   TPM Quote + TPM Certify verification
│   └── AkCollateralVerifier.sol  #   AK certificate chain validation
├── interfaces/                   # Contract interfaces
├── types/                        # Data structures (Common.sol, Evidence.sol, Constants.sol)
├── lib/                          # Utility libraries
└── mock/                         # Mock contracts for testing
crates/
└── automata-tee-workload-measurement/  # Rust client SDK
script/                                 # Foundry deployment & configuration scripts
test/                                   # Integration tests and benchmarks
```

## Documentation

- **[Developer Guide](./docs/DEVELOPER_GUIDE.md)** — Detailed technical documentation covering each registry, the 9-step verification workflow, session lifecycle, and data structures
- **[Integration Guide](./docs/INTEGRATION_GUIDE.md)** — How to integrate via the Rust client SDK or your own Solidity smart contract

## Deployment

### Hoodi Testnet

| Contract | Address |
| --- | --- |
| SessionRegistry | `0xB247950fBBFCE245641e433AFd7d8884328CE5A1` |
| BaseImageRegistry | `0xCbe56f9B73c822679Cf36DcF8D99434E0f1588Ca` |
| WorkloadRegistry | `0xda6430E06385F7516963f8A3B4e87beBb89860F8` |
| TeeVerifier | `0xCfC1B6Bb1A177d46271B3938f264a484b9F7559f` |
| SignatureVerifier | `0xc52B7390DFb82CC4e2241B4a2586428532D76f18` |
| KeyResolver | `0x77B4f0c3Ab93bF3c624E8B72EdD12736D6B36C51` |
| MaaKeyRegistry | `0x8451786c90260Da9441A2847Fb1e3DD8E5B207c3` |

## Related Projects

- [DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation) - On-chain verification of Intel SGX/TDX DCAP attestations
- [TDX Attestation SDK](https://github.com/automata-network/tdx-attestation-sdk) - TDX Development SDK to generate Intel TDX quotes from cloud providers
- [AMD SEV-SNP Attestation SDK](https://github.com/automata-network/amd-sev-snp-attestation-sdk) - On-chain verification of AMD SEV-SNP attestations
- [AWS Nitro Enclave Attestation](https://github.com/automata-network/aws-nitro-enclave-attestation) - On-chain verification of AWS Nitro Enclave attestations
- [TPM Attestation](https://github.com/automata-network/automata-tpm-attestation) - On-chain verification of TPM Quote and TPM certificates management
- [CVM Base Image](https://github.com/automata-network/cvm-base-image) - Tools for deploying Confidential VMs with workloads on GCP, AWS, and Azure

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Support

For questions and support, please open an issue.
