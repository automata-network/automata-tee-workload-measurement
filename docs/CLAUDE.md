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
   - `verifyAttestation()`: Returns TEE verified data, TEE output, and measurement
4. Validate returned measurement against golden measurement

## CVM Registry Use Case

The `CVMRegistry.sol` contract provides a production-ready implementation for managing Confidential VM workload identities and their attestation lifecycle. This contract demonstrates how to build a trust registry on top of the WorkloadVerifier.

### Key Features
- **Identity Management**: Maps CVM workload identity (TPM-generated public key) to attestation configuration
- **TPM2_Certify Key Certification**: CVM identity key certified by TPM Attestation Key, guaranteeing owner cannot read private key
- **Attestation Lifecycle**: Supports initial registration, refresh, and key rotation
- **TTL Management**: Single configurable time-to-live (30 days default)
- **AK Binding**: One-to-one binding between Attestation Key and CVM identity
- **Replay Protection**: Built-in for TEE reports and TPM quotes (apps must implement own message replay protection)

### Core Workflows

#### 1. Registration (`registerCvm`)
- No signature required (bootstrap via attestation and TPM2_Certify binding)
- Verifies TEE report and TPM quote through WorkloadVerifier
- Verifies CVM identity key is certified by AK via TPM2_Certify
- Checks AK is not already bound to another identity
- Stores configuration with expiration timestamp, measurement hash, and AK binding

#### 2. Refresh (`refreshCvm`)
- Extends CVM validity with fresh TEE and TPM attestations
- No signature required
- Verifies AK binding matches registered identity
- Updates expiration timestamp and measurement hash
- Does NOT support identity rotation (use rotateCvmIdentityKey instead)

#### 3. Key Rotation (`rotateCvmIdentityKey`)
- Rotates identity key while TEE report is still valid
- New key must be certified by same AK via TPM2_Certify
- Revokes old identity and updates AK binding
- Saves gas by reusing existing attestation data

### Implementation Details

#### CVMIdentity Structure
```solidity
struct CVMIdentity {
    bytes tpmtPublic;           // TPM public key in TPMT_PUBLIC format
    SignatureAlgorithm sigAlgo; // Signature scheme and hash algorithm
}
```

#### Identity Hash Computation
Public key is extracted from `tpmtPublic`, then:
```solidity
keccak256(abi.encodePacked(
    sigAlgo.scheme,
    pubkey.params,
    sigAlgo.hashAlgo,
    pubkey.data
))
```

#### TPM2_Certify Certification
```solidity
struct CVMIdentityCertification {
    bytes certInfo;           // TPMS_ATTEST from TPM2_Certify
    bytes akCertificationSig; // AK signature over certInfo
}
```
The contract verifies:
- AK signature over certInfo is valid
- Certified key name matches provided tpmtPublic
- AK used for certification matches verified AK from TEE attestation

#### Message Domain Separation (for Apps using CVMSignature)
```
abi.encodePacked(bytes(prefix), block.chainid, address(this), userData)
```
Default prefix:
- `CVM_WORKLOAD_USER_MESSAGE` (apps can define custom prefixes)

### Security Considerations
- **TPM2_Certify Chain of Trust**: TEE → AK → CVM Identity Key ensures private key cannot be read by CVM owner
- **AK Binding**: One-to-one mapping between AK and CVM identity prevents AK reuse across identities
- **Replay Protection**: TEE reports and TPM quotes cannot be reused (hash-based tracking)
- **Identity Revocation**: Rotated identities are marked as revoked to prevent re-registration
- **Measurement Normalization**: Zeros TDX rtmr3 for stability across reboots
- **Immutable WorkloadVerifier**: Reference fixed at deployment prevents verification bypass
- **App-Level Replay Protection**: Applications MUST implement their own nonce/timestamp-based replay protection for signed messages

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