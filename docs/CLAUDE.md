# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository implements on-chain verification of Confidential VM (CVM) workloads using TEE (Trusted Execution Environment) attestation. The system verifies the integrity and measurement of workloads running on Intel TDX or AMD SEV-SNP hardware, hosted on Azure or Google Cloud Platform.

## Key Architecture Components

### Core Contract Structure
- **`WorkloadVerifier.sol`**: Main entry point for workload attestation verification
  - Integrates TEE attestation (Intel TDX, AMD SEV-SNP)
  - TPM quote verification for workload measurements
  - Supports both cloud providers (Azure, GCP)

### Verification Flow
1. Application submits TEE attestation report + workload collateral to `WorkloadVerifier`
2. TEE report verified via DCAP (Intel TDX) or ZK proofs (AMD SEV-SNP)
3. TPM quote and signature verified against Attestation Key
4. PCR measurements validated against provided values
5. Report ID binding between TEE and TPM verified
6. Final measurement hash generated for workload integrity

### Dependencies
- **DCAP Attestation**: Intel TDX verification (onchain, ~5M gas)
- **SEV-SNP Attestation**: AMD verification via ZK proofs (RiscZero Groth16, ~240k gas)
- **TPM Attestation**: TPM quote verification with PCR measurement validation
- **P256 Verifier**: ECDSA verification for GCP (daimo-p256 contract)

## Common Development Commands

### Building
```bash
# Compile all contracts with size output
forge build --sizes

# Clean build
forge clean && forge build
```

### Testing
```bash
# Run all tests
forge test

# Run specific test file
forge test --match-path test/CvmAzureTest.t.sol

# Run specific test function
forge test --match-test testVerifyAzureTdx

# Run tests with verbosity (shows logs)
forge test -vv  # Basic logs
forge test -vvv # Detailed logs
forge test -vvvv # Traces for all tests

# Run tests with gas reporting
forge test --gas-report
```

### Deployment
```bash
# Deploy contracts (uses script/Deploy.s.sol)
forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast

# Deploy CVM specific contracts
forge script script/cvm/DeployCVM.s.sol --rpc-url <RPC_URL> --broadcast
```

### Code Quality
```bash
# Format Solidity files
forge fmt

# Check formatting without making changes
forge fmt --check

# Generate coverage report
forge coverage

# Run static analysis with Slither (if installed)
slither .
```

## Project Structure Insights

### Contract Organization
- `/src/interfaces/`: Public interfaces for external integration
  - `IWorkloadVerifier.sol`: Main verification interface
  - `ITeeVerifier.sol`: TEE-specific verification interfaces
- `/src/lib/`: Core libraries and data structures
  - `LibTEE.sol`: TEE types and enums (TEEType, CloudType, TeeReportType)
  - `LibWorkload.sol`: Workload measurement structures
- `/src/mock/`: Mock contracts for testing
- `/src/usecases/`: Example implementation patterns

### Testing Approach
- Tests use `forge-std` Test framework
- `TestSetup.sol` provides common test infrastructure
- Tests are organized by cloud provider (CvmAzureTest, CvmGcpTest)
- Mock attestation supported for development/testing

### Gas Optimization Considerations
- Contract uses `via_ir` optimizer for better gas efficiency
- Different verification paths have vastly different gas costs:
  - Azure TDX: ~5M gas (onchain DCAP)
  - GCP with secp256r1: ~330k per signature (3450 gas with RIP 7212)
  - ZK proofs for AMD SEV-SNP: ~240k gas

### Critical Implementation Details

1. **Report ID Binding**: Essential for TEE-TPM binding verification
   - Azure TDX: AK hash in report data
   - GCP TDX: UUID in rtmr3 (expensive sha384 computation)

2. **Certificate Chain Handling**:
   - GCP requires full AK certificate chain
   - Azure uses varDataJson for AK extraction
   - Intermediate certificates cached for gas optimization

3. **PCR Measurement Validation**:
   - Supports both deterministic PCR values and event logs
   - PCR selection bitmap must match quote
   - Hash chain verification for measurement integrity

4. **Cloud-Specific Differences**:
   - Azure: RSA signatures, AK hash in TEE report
   - GCP: secp256r1 signatures, certificate chain verification

## Integration Guidelines

When integrating `WorkloadVerifier`:
1. Deploy or connect to existing verifier contract
2. Prepare TEE attestation report and workload collateral
3. Call appropriate verification method based on needs:
   - `verifyAttestation()`: Returns TEE verified data
   - `verifyAttestationAndGetMeasurement()`: Returns full measurement object
   - `verifyAttestationAndGetMeasurementHash()`: Returns measurement hash only
4. Validate returned measurement against golden measurement
5. Check TPM extraData for application-specific validation

## CVM Registry Use Case

The `CVMRegistry.sol` contract provides a production-ready implementation for managing Confidential VM workload identities and their attestation lifecycle. This contract demonstrates how to build a trust registry on top of the WorkloadVerifier.

### Key Features
- **Identity Management**: Maps CVM workload identity (TPM-generated public key) to attestation configuration
- **Attestation Lifecycle**: Supports initial registration, re-attestation, and key rotation
- **TTL Management**: Configurable time-to-live for TEE reports (30 days default) and TPM quotes (60 days default)
- **Signature Verification**: Domain-separated message signing for secure operations
- **Upgradeability**: UUPS proxy pattern for contract upgrades

### Core Workflows

#### 1. Initial Registration (`attestCvm`)
- No signature required (bootstrap via attestation binding)
- Verifies TEE report and TPM quote through WorkloadVerifier
- Extracts identity from TPM extraData and validates binding
- Stores configuration with both TEE and TPM timestamps

#### 2. TPM-Only Re-attestation (`reattestCvmWithTpm`)
- Used when TPM collateral expired but TEE still valid
- Requires signature from current CVM identity
- Updates TPM timestamp and measurement hash
- Supports key rotation if new identity provided in TPM extraData

#### 3. TTL Configuration (`setCollateralTTL`)
- Requires signature from CVM identity
- Updates TEE and TPM time-to-live values
- Uses nonce for replay protection

### Implementation Details

#### Identity Hash Computation
```solidity
keccak256(abi.encodePacked(
    cvmIdentity.sigAlgo.scheme,
    cvmIdentity.pubkey.params,
    cvmIdentity.sigAlgo.hashAlgo,
    cvmIdentity.pubkey.data
))
```

#### TPM Extra Data Format
```
uint8 magic_prefix || bytes32 cvmIdentityHash || bytes nonce
```
Maximum 50 bytes to support all cloud providers (Azure/GCP/AWS)

#### Message Domain Separation
```
abi.encodePacked(bytes(prefix), block.chainid, address(this), userData)
```
Prefixes:
- `CVM_WORKLOAD_REATTEST_TPM`
- `CVM_WORKLOAD_TTL_CONFIG`
- `CVM_WORKLOAD_USER_MESSAGE`

### Security Considerations
- Nonce-based replay protection per identity
- Measurement normalization (zeros TDX rtmr3 for stability)
- Identity binding verified through TPM extraData
- Immutable WorkloadVerifier reference prevents verification bypass

## Known Limitations & Considerations

- X.509 Key Usage and Basic Constraints not validated (medium priority fix needed)
- Full certificate chain required on every call (gas inefficient but secure)
- Manual ASN.1 parsing is fragile to structure variations

## Acknowledged Design Decisions

### ECDSA Signature Format (Issue #2)
**Decision**: The system explicitly requires ECDSA signatures to be exactly 64 bytes in `r || s` format (32 bytes each).

**Justification**: This is an intentional design choice to:
- Standardize the signature format across all integrations
- Avoid the complexity and gas costs of DER encoding/decoding on-chain
- Ensure predictable behavior and gas consumption

**Impact**: Callers must ensure signatures are provided in this exact format. Any DER-encoded signatures must be converted to raw `r || s` format before submission.

### Compressed P-256 Keys Not Supported (Issue #4)
**Decision**: The system explicitly rejects compressed P-256 public keys and only accepts uncompressed keys.

**Format Requirements**:
- P-256 public keys must be exactly 64 bytes consisting of `x || y` coordinates (32 bytes each)
- The 0x04 uncompressed point prefix is NOT included in the 64-byte requirement
- Compressed keys (33 bytes with 0x02 or 0x03 prefix) are not supported

**Justification**: 
- Converting compressed keys to uncompressed format on-chain would be computationally expensive
- The decompression operation requires complex elliptic curve point arithmetic
- Gas costs for such operations would significantly impact the economic viability of verification

**Impact**: TPMs and certificate issuers must be configured to use uncompressed P-256 public keys. The system expects the raw x and y coordinates without the uncompressed point indicator prefix.