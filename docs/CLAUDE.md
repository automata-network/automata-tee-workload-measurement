# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **hybrid Solidity + Rust project** for onchain verification and management of Confidential VM (CVM) workloads. It provides cryptographic attestation of TEE (Trusted Execution Environment) measurements to prove workload integrity for Intel TDX and AMD SEV-SNP CVMs on Azure and Google Cloud Platform.

**Key Components:**
1. **Solidity Contracts** (`src/`) - EVM smart contracts for onchain attestation verification
2. **Rust SDK** (`crates/`) - Client library bindings to interact with the contracts
3. **Foundry Scripts** (`script/`) - Deployment and configuration automation

## Development Commands

### Solidity Development (Foundry)

```bash
# Build all contracts
forge build

# Run all tests
forge test

# Run specific test
forge test --match-contract SessionRegistryTest

# Run test with verbosity (for debugging)
forge test --match-test test_registerSession -vvvv

# Format contracts
forge fmt

# Generate gas report
forge test --gas-report

# Check for compilation issues without running tests
forge build --force
```

### Rust Development

```bash
# Build Rust crates
cargo build

# Run Rust tests
cargo test

# Format Rust code
cargo fmt

# Check for issues
cargo clippy
```

### Deployment

Deployment scripts are located in `script/`. The project uses Foundry's scripting system with environment-based configuration.

**Setup:**
1. Copy `.env.example` to `.env` and configure:
   - `DCAP_ATTESTATION_ADDR` - Intel TDX DCAP attestation verifier
   - `SNP_ATTESTATION_ADDR` - AMD SEV-SNP attestation verifier
   - `TPM_ATTESTATION_ADDR` - TPM quote verifier
   - `P256_VERIFIER` - P256 signature verifier (precompile or contract)
   - `RPC_URL` - Target network RPC endpoint
   - `OWNER` - Deployer/owner address

**Deploy to testnet:**
```bash
# Deploy all production contracts (TeeVerifier, SignatureVerifier, registries)
forge script script/DeployProd.s.sol:DeployProd --rpc-url $RPC_URL --broadcast --verify

# Deploy mock contracts for testing
forge script script/DeployMock.s.sol:DeployMock --rpc-url $RPC_URL --broadcast
```

**Configuration scripts:**
```bash
# Whitelist management (when registry is paused)
forge script script/Config.s.sol --sig "updateBaseImageWhitelist(bytes32,bool)" <fingerprint> true --rpc-url $RPC_URL --broadcast

# Enable/disable whitelist enforcement
forge script script/Config.s.sol --sig "enableBaseImageRegistryWhitelist(bool)" true --rpc-url $RPC_URL --broadcast
```

Deployment addresses are saved to `deployment/<chain-id>.json`.

**Dev-fork bootstrap:** `BaseImageRegistry` / `WorkloadRegistry` deploy paused (= whitelist enforced). Before publishes on a fresh fork, run `Config.s.sol::enable{BaseImage,Workload}RegistryWhitelist(false)`.

## Debug

- Decode a custom-error selector: `cast 4byte 0xXXXXXXXX` (4byte.directory). If unlisted, grep `src/` for `error <Name>(` then `cast sig "<Name>(<types>)"`.

## Architecture

### Three-Tier Registry System

The system uses a **hierarchical registry architecture** to enforce workload integrity policies:

```
SessionRegistry (orchestrator)
├── BaseImageRegistry (OS/platform)
│   ├── BaseImage (Ubuntu 24.04, NixOS, etc.)
│   ├── PlatformProfile (GCP TDX, Azure SNP, etc.)
│   └── MeasurementVariant (machine-type overrides)
├── WorkloadRegistry (application)
│   └── WorkloadSpec (application PCR and attribute policy)
├── AmdSnpSecurityPolicyRegistry (AMD policy defaults by exact CPUID)
├── TeeSecurityPolicyVerifier (TEE and metadata policy evaluation)
├── TeeVerifier (TEE attestation)
├── AkCollateralVerifier (Azure MAA and GCP AK collateral)
└── SignatureVerifier (owner authentication)
```

**Key Principles:**
- **Separation of Concerns**: BaseImage (privileged), Workload (unprivileged), Session (runtime)
- **Immutable Verifiers**: TeeVerifier and TeeSecurityPolicyVerifier can be reused across registries
- **Upgradeable Registries**: BaseImageRegistry, WorkloadRegistry,
  SessionRegistry, AmdSnpSecurityPolicyRegistry, MaaKeyRegistry, and
  KeyResolver use UUPS proxies
- **Whitelist Mode**: Registries can operate in permissioned mode during initial rollout

### Session Registration Verification Flow

When a CVM registers a session via `SessionRegistry.registerSession()`, the system performs:

1. **Policy lookup** - Resolve the workload, base image, platform profile, and measurement variant.
2. **TEE attestation** - Verify the Intel TDX quote or AMD SEV-SNP report.
3. **Verified TEE and attribute policy** - Call `TeeSecurityPolicyVerifier.verifyTeePolicy`. It evaluates ordinary attributes first, then the applicable reserved TEE attributes. The active exact-CPUID `AmdSnpSecurityPolicyRegistry` record supplies missing AMD packed values.
4. **AK collateral and TEE-AK binding** - Verify the TPM Attestation Key and bind it to the verified TEE report.
5. **TPM Quote** - Verify the Quote signature, nonce, and PCR values.
6. **TPM Certify** - Verify that the TPM signing key is certified by the AK.
7. **Session key delegation** - Verify that the TPM signing key authorized the session key.
8. **PCR policy** - Evaluate platform-profile invariants, measurement-variant overrides, and every workload PCR rule.
9. **Owner authorization** - Verify the owner signature and create the session.

**PCR Verification Types:**
- `STATIC` - Exact PCR value match (fixed measurement)
- `DYNAMIC_SUBSET` - required landmarks must occur in PCR events (any order; extra events permitted)
- `DYNAMIC_SUBSEQUENCE` - PCR events must contain required sequence (ordered)
- `DYNAMIC_INDEXED_EVENT_SETS` - exact event count plus checked indexes with allowed digest sets

### Contract Inheritance Hierarchy

**SessionRegistry** (the main orchestrator):
```
SessionRegistry
├── ISessionRegistry
├── OwnableUpgradeable (admin control)
└── UUPSUpgradeable (upgradeability pattern)
```

`SessionRegistry` calls separately deployed `TpmVerifier` and
`IAkCollateralVerifier` contracts. It also holds immutable
`ITeeVerifier`, `ISignatureVerifier`, `IBaseImageRegistry`,
`IWorkloadRegistry`, and `ITeeSecurityPolicyVerifier` references.

**BaseImageRegistry / WorkloadRegistry**:
```
{BaseImage|Workload}Registry
├── OwnableUpgradeable (admin control)
├── PausableUpgradeable (whitelist enforcement)
└── UUPSUpgradeable (upgradeability pattern)
```

**TeeVerifier** (stateless dispatcher):
- Dispatches to `IDcapAttestation` (Intel TDX via DCAP) or `ISnpAttestation` (AMD SEV-SNP)
- Supports onchain Solidity verification and ZK proof backends (RiscZero, SP1)

### Key Data Structures

**PublicIdentity** - Generic public key representation:
- `typeId` - Algorithm ID (ES256K, RSA-2048, P256, etc.)
- `key` - DER/SPKI/raw bytes encoding

**PcrSpec** - PCR measurement policy:
- `pcrIndex` - PCR slot (0-23)
- `comparison` - Opaque canonical ABI comparison bytes decoded only by `TpmVerifier`

**CVMSession** - Registered CVM identity:
- `sessionKeyFingerprint` - Current operational key
- `baseImageId / workloadId` - Policy identifiers
- `sessionExpiresAt` - Absolute session expiry

Owner replay-protection nonces live in a separate `SessionRegistry` mapping;
they are not fields in `CVMSession`.

### Code Organization

**Solidity (`src/`)**:
- `SessionRegistry.sol` - Attestation verification and session lifecycle
- `ZkVerifierRegistry.sol` - exact proof type, backend, program identifier, and verifier adapter routes
- `BaseImageRegistry.sol` - OS/platform policy management
- `WorkloadRegistry.sol` - Application policy management
- `AmdSnpSecurityPolicyRegistry.sol` - AMD SEV-SNP policy defaults by exact CPUID
- `TeeSecurityPolicyVerifier.sol` - Ordinary metadata and reserved TEE security-policy evaluation
- `MaaKeyRegistry.sol` - Microsoft Azure Attestation signing-key directory
- `TeeVerifier.sol` - TEE attestation dispatcher
- `SignatureVerifier.sol` - ECDSA/RSA signature verification
- `KeyResolver.sol` - Future: ENS-style key resolution (not yet integrated)
- `bases/` - Separately deployed TPM and Attestation Key collateral verifiers plus shared TPM code
- `interfaces/` - Contract interfaces and storage structs
- `types/` - Common data structures (Common.sol, Evidence.sol, Constants.sol)
- `lib/` - Utility libraries (LibKey, LibBytes, Sha2Ext, Asn1Decode, BytesUtils)
- `mock/` - Mock contracts for testing (MockAutomataDcapAttestation, etc.)

**Rust (`crates/automata-tee-workload-measurement/`)**:
- `session_registry.rs` - SessionRegistry contract bindings
- `base_image_registry.rs` - BaseImageRegistry bindings
- `workload_registry.rs` - WorkloadRegistry bindings
- `relay.rs` - Transaction relay utilities
- `stubs.rs` - Mock implementations for testing
- `types.rs` - Rust type definitions matching Solidity structs
- `workload_measurement.rs` - High-level API wrappers

**Scripts (`script/`)**:
- `DeployProd.s.sol` - Production deployment
- `DeployMock.s.sol` - Mock deployment for testing
- `Deploy{Contract}.s.sol` - Individual contract deployment scripts
- `Config.s.sol` - Whitelist and configuration management
- `utils/` - Shared deployment utilities (DeploymentConfig, etc.)
- `cvm/generate-init-data.sh` - CVM initialization script

**Tests (`test/`)**:
- `SessionRegistry.t.sol` - Main integration tests
- `fixtures/` - Test data (TPM quotes, certificates, etc.)
- `benchmark/` - Gas benchmarking tests
- `utils/` - Test utilities

### External Dependencies

**Solidity Libraries:**
- `@openzeppelin/contracts-upgradeable` - Proxy pattern, access control
- `@automata-network/automata-tpm-attestation` - TPM verification primitives
- `@solady` - Gas-optimized utilities

**Verification Backends:**
- DCAP Attestation (`IDcapAttestation`) - Intel TDX quote verification
- SNP Attestation (`ISnpAttestation`) - AMD SEV-SNP report verification
- TPM Attestation (`ITpmAttestation`) - TPM quote and certificate verification
- P256 Verifier - ECDSA P256 signature verification (RIP-7212 precompile)

## Common Workflows

### Adding a New Base Image

1. Register owner public key in `BaseImageRegistry` whitelist (if paused)
2. Create `BaseImageSpec` with PCR policies for boot components. PCR 0 through
   19 is the usual platform convention, not a contract-enforced range.
3. Register platform profiles (GCP, Azure, AWS) with TEE-specific attributes
4. Register measurement variants for different machine types
5. Call `BaseImageRegistry.registerBaseImage()` with owner signature

### Adding a New Workload

1. Register owner public key in `WorkloadRegistry` whitelist (if paused)
2. Create `WorkloadSpec` with application PCR policies. PCR 20 through 23 is
   the usual workload convention, not a contract-enforced range.
3. Define access control (ANY, WHITELIST, BLACKLIST) for base images
4. Call `WorkloadRegistry.registerWorkload()` with owner signature

### Registering a CVM Session

1. Boot CVM with TPM, generate TEE attestation and TPM quote
2. Collect evidence: TEE report, TPM quote, AK collateral, TPM2_Certify proofs
3. Sign registration message with owner key
4. Call `SessionRegistry.registerSession()` - performs the complete registration verification sequence
5. Store returned `sessionId` - use for session key verification downstream

### Rotating Session Keys

Use `SessionRegistry.rotateKey()` when:
- Session is still valid (not expired)
- Want to rotate to new session key without full TEE re-attestation
- Need fresh TPM2_Certify proof for new key
- Do not want to extend `sessionExpiresAt`

Use `SessionRegistry.renewSession()` to extend the lifecycle with fresh TEE and
TPM attestation plus predecessor TPM authorization. Use
`SessionRegistry.recoverSession()` with fresh attestation and owner
authorization when the predecessor TPM key is unavailable.

## Important Notes

- **Solc Version**: Fixed at `0.8.27` with `via_ir = true` optimizer
- **EVM Version**: `prague` (latest opcodes)
- **Proxy Pattern**: All registries use UUPS (Universal Upgradeable Proxy Standard)
- **Storage Gaps**: All upgradeable contracts reserve storage slots (`__gap`) for future fields
- **P256 Verifier**: Depends on RIP-7212 precompile at `0x0000000000000000000000000000000000000100` or fallback contract
- **FFI Enabled**: `foundry.toml` has `ffi = true` for test data generation scripts
- **Gas Optimization**: Complex verification logic benefits from `via_ir` compilation
- **Immutable References**: TeeVerifier, SignatureVerifier, registry dependencies are immutable in SessionRegistry
