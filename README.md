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
SessionRegistry (attestation verification and session lifecycle)
├── BaseImageRegistry (OS/platform PCR and attribute policies)
│   ├── BaseImage (name, version, URI)
│   ├── PlatformProfile (cloud + TEE config, invariant PCRs, platform attributes)
│   └── MeasurementVariant (machine-type PCR overrides, machine attributes)
├── WorkloadRegistry (application PCR and attribute policies)
│   └── WorkloadSpec (container measurements, attribute requirements, base image access control)
├── AmdSnpSecurityPolicyRegistry (default policy for each exact AMD CPUID)
├── TeeVerifier (dispatches to DCAP/SNP attestation verifiers; supports ZK backends)
├── AkCollateralVerifier (Azure MAA JWT and GCP AK certificate-chain verification)
├── MaaKeyRegistry (Azure MAA signing-key directory)
├── SignatureVerifier (RS256, ES256, ES256K)
└── KeyResolver (public key fingerprint → PublicIdentity directory)
```

The usual PCR split is a convention. The contracts require sorted PCR indexes
below 24 but do not enforce a fixed platform-versus-workload range.

`TeeVerifier` extracts six authorable Intel TDX and AMD SEV-SNP
security-policy inputs plus the AMD SEV-SNP report version and version-5
mitigation vectors from verified reports. `SessionRegistry` sends the effective profile,
variant, and workload attributes to `AmdSnpSecurityPolicyRegistry`. That
registry evaluates ordinary metadata first, then only the reserved attributes
for the verified TEE type. Intel TDX TCB status uses a configurable one-hot
mask. AMD SEV-SNP TCB and `PLATFORM_INFO` checks also require the active
`AmdSnpSecurityPolicyRegistry` record for the report's exact CPUID. That
record also applies mandatory mitigation-vector masks that authors cannot
override.

**Key Principles:**
- **Separation of Concerns** — Base images (privileged OS), workloads (unprivileged apps), and sessions (runtime identity) are managed independently
- **PublicIdentity Ownership** — Registry ownership is based on cryptographic keys, independent of EVM addresses
- **Immutable Verifiers** — `TeeVerifier` and `SignatureVerifier` are stateless and reusable across registries
- **Upgradeable Registries** — `BaseImageRegistry`, `WorkloadRegistry`,
  `SessionRegistry`, `AmdSnpSecurityPolicyRegistry`, `MaaKeyRegistry`, and
  `KeyResolver` use UUPS proxies

## Project Structure

```
src/
├── SessionRegistry.sol           # Attestation verification and session lifecycle
├── BaseImageRegistry.sol         # OS/platform measurement policy management
├── WorkloadRegistry.sol          # Application measurement policy management
├── AmdSnpSecurityPolicyRegistry.sol # AMD SEV-SNP policy defaults by CPUID
├── MaaKeyRegistry.sol            # Microsoft Azure Attestation signing keys
├── TeeVerifier.sol               # TEE attestation dispatcher (DCAP / SNP / ZK)
├── SignatureVerifier.sol          # Cryptographic signature verification (RS256, ES256, ES256K)
├── KeyResolver.sol               # Public key fingerprint directory
├── bases/                        # Base verification contracts
│   ├── TpmVerifier.sol           #   TPM Quote + TPM Certify verification
│   └── AkCollateralVerifier.sol  #   Azure MAA JWT and GCP AK validation
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

- **[Developer Guide](./docs/DEVELOPER_GUIDE.md)** — Detailed technical documentation covering each registry, the session registration verification sequence, session lifecycle, and data structures
- **[Integration Guide](./docs/INTEGRATION_GUIDE.md)** — How to integrate via the Rust client SDK or your own Solidity smart contract

## Deployment

The verified TEE attribute implementation is not the older Hoodi deployment
recorded in `deployment/560048.json`. It adds
`AmdSnpSecurityPolicyRegistry` and changes the immutable dependencies of
`SessionRegistry`. Verify the proxy implementations and every immutable
dependency from live chain state before using a deployment.

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
