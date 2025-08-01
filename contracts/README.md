# Automata TEE Workload Measurement (EVM Smart Contract)

This document describes the EVM implementation for onchain verification and measurement of the workload of a Confidential VM (CVM) instance hosted on cloud service providers.

TEE Onchain Workload Measurement implementation can be found [`WorkloadVerifier.sol`](./src/WorkloadVerifier.sol), which is dependent on:

1. [Automata DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation/tree/main/evm) to verify Intel TDX quotes
2. [Automata SEV-SNP Attestation](https://github.com/automata-network/amd-sev-snp-attestation-sdk/tree/main/zk/contracts) to verify AMD SEV SNP attestation reports.
3. [Automata TPM Attestation](https://github.com/automata-network/automata-tpm-attestation) to verify TPM quote, checking PCR measurements and user provided data.

---

## #BUIDL 🛠️

1. Install [`Foundry`]().

2. Make sure you are on the `/contracts` directory, then install the dependencies.

```shell
forge install
```

3. Compile the contracts.

```shell
forge build --sizes
```

4. Run the tests.

```shell
forge test
```

---

## Integration

### Installation

To integrate WorkloadVerifier into your project, install it as a Foundry dependency:

```shell
forge install automata-network/tee-workload-measurement
```

### Import Remapping

Add the following remapping to your `foundry.toml` file:

```toml
[profile.default]
remappings = [
    "@automata-network/tee-workload-measurement/=lib/tee-workload-measurement/contracts/src/"
]
```

### Basic Usage

Here's a simple example of how to integrate WorkloadVerifier into your contract:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IWorkloadVerifier, WorkloadCollaterals} from "@automata-network/tee-workload-measurement/interfaces/IWorkloadVerifier.sol";
import {TEEType, TeeReportType, CloudType} from "@automata-network/tee-workload-measurement/lib/LibTEE.sol";

contract MyContract {
    IWorkloadVerifier public immutable workloadVerifier;
    
    constructor(address _workloadVerifier) {
        workloadVerifier = IWorkloadVerifier(_workloadVerifier);
    }
    
    function verifyWorkload(
        bytes32 userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata workloadCollaterals
    ) external payable returns (bytes32 measurementHash) {
        measurementHash = workloadVerifier.verifyAttestation(
            userDataHash,
            teeType,
            teeReportType,
            cloudType,
            teeAttestationReport,
            workloadCollaterals
        );
        
        // Use the measurement hash for your application logic
        // e.g., compare against expected values, store for future reference
    }
}
```

---

## API Reference

### Core Interface

#### `verifyAttestation`

```solidity
function verifyAttestation(
    bytes32 _userDataHash,
    TEEType teeType,
    TeeReportType teeReportType,
    CloudType cloudType,
    bytes calldata _teeAttestationReport,
    WorkloadCollaterals calldata _workloadReport
) external payable returns (bytes32);
```

Verifies the integrity of a CVM workload and returns the golden measurement hash.

**Parameters:**
- `_userDataHash`: The hash of the user data to be verified
- `teeType`: The TEE technology used (`IntelTdx` or `AmdSevSnp`)
- `teeReportType`: The report verification method (`Solidity` for onchain or `ZkRiscZero`/`ZkSp1` for ZK proofs)
- `cloudType`: The cloud provider (`Azure` or `Gcp`)
- `_teeAttestationReport`: The TEE attestation report data
- `_workloadReport`: Additional verification data (see WorkloadCollaterals below)

**Returns:**
- `bytes32`: The golden measurement hash representing the verified workload

### Data Structures

#### `WorkloadCollaterals`

```solidity
struct WorkloadCollaterals {
    bytes tpmQuote;        // TPM quote to be verified
    bytes tpmSignature;    // Signature for the TPM quote
    MeasureablePcr[] pcrs; // Platform Configuration Register values
    bytes reportId;        // Report identifier (UUID for TDX on GCP)
    bytes akPub;           // Attestation Key public key (GCP) or varDataJson (Azure)
    bytes[] certs;         // Certificate chain (GCP only, empty for Azure)
}
```

#### `GoldenMeasurement`

```solidity
/**
 * @dev must provide either TDX or SNP Reports. 
 * (both cannot simultaneously contain value or empty)
 */
struct GoldenMeasurement {
    Pcr[] pcrs;            // PCR values and/or selected event logs that a workload must produce
    TdxMeasurement tdx;    // TD 1.0 Report Body
    SnpMeasurement snp;    // AMD SEV SNP Report Body
}
```

#### Enums

- **`TEEType`**: `IntelTdx`, `AmdSevSnp`
- **`TeeReportType`**: `Solidity`, `ZkRiscZero`, `ZkSp1`
- **`CloudType`**: `Azure`, `Gcp`

### View Functions

The interface provides access to underlying attestation contracts:

- `dcapAttestation()`: Returns the DCAP attestation contract for Intel TDX verification
- `snpAttestation()`: Returns the SNP attestation contract for AMD SEV-SNP verification
- `tpmAttestation()`: Returns the TPM attestation contract for TPM quote verification
- `allowMockAttestation()`: Returns whether mock attestation is enabled (for testing)

### Golden Measurement Hash

The golden measurement hash returned by `verifyAttestation()` is a cryptographic proof of workload integrity that represents:

- **Workload Identity**: A unique fingerprint of the verified CVM workload
- **Integrity Assurance**: Cryptographic proof that the workload hasn't been tampered with
- **Compliance Evidence**: Verifiable proof for regulatory or security requirements

**Use Cases:**

1. **Integrity Verification**: Compare the returned hash against expected measurement values to ensure workload authenticity
2. **Trust Chains**: Store the hash onchain to build verifiable trust relationships between different workloads
3. **Compliance Tracking**: Use the hash as evidence for audit trails and regulatory compliance
4. **Access Control**: Gate access to sensitive operations based on verified workload measurements
5. **Reputation Systems**: Build reputation scores based on consistently verified workload behavior

**Example Usage:**

```solidity
// Store expected measurement for a trusted workload
bytes32 public trustedWorkloadHash = 0x123...;

function verifyTrustedWorkload(/* parameters */) external {
    bytes32 measurementHash = workloadVerifier.verifyAttestation(/* args */);
    
    require(measurementHash == trustedWorkloadHash, "Untrusted workload");
    
    // Proceed with trusted operations
    _executeSensitiveOperation();
}
```

---

## Gas Benchmark

The table below shows our initial finding on gas costs to measure CVMs with various TEEs hosted on Azure and GCP.

|  | TEE Report Verification Gas Cost | AK Pubkey Verification Gas Cost | TPM Signature Verification Gas Cost | PCRs and User Data Matching Gas Cost | Report ID Binding Check Gas Cost | Golden Measurement Hashing Gas Cost |
| --- | --- | --- | --- | --- | --- | --- |
| Azure TDX | ~5M[^1] gas (Onchain DCAP) | 49k[^2] gas | 37k gas (RSA) | 10k gas | 3k gas | 13k gas |
| Azure AMD-SEV-SNP | 240k[^3] gas (RiscZero Groth16) | 49k[^2] gas | 37k gas (RSA) | 10k gas | 3k gas | 13k gas |
| GCP TDX | ~5M[^1] gas (Onchain DCAP) | 384k[^4] gas | 335k[^1] gas (secp256r1) | 10k gas | 482k[^5] gas | 26k gas |
| GCP AMD-SEV-SNP | 240k[^3] gas (RiscZero Groth16) | 384k[^4] gas | 335k[^1] gas (secp256r1) | 19k gas | 5k gas | 25k gas |

### Remark:

[^1]: secp256r1 ECDSA is executed with the [daimo-p256](https://github.com/daimo-eth/p256-verifier) contract. The gas cost is about 330k per signature. EVM Chains that implement [RIP 7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) can significantly reduce cost to only 3450 gas per signature.

[^2]: TEE Attestation Report generated by CVMs on Azure already contains the hash of the TPM Attestation Key, hence confirming its association with the TPM quote. This step merely parses `azure_var.json` to extract the TPM Attestation public key. This step will fail if the users did not provide `azure_var.json` as part of the workload collateral.

[^3]: AMD-SEV-SNP attestation report currently can only be verified onchain using SNARK proofs. The proof provided in our test is generated by a [RiscZero Guest Program](https://github.com/automata-network/amd-sev-snp-attestation-sdk/tree/v2/crates/risc0-methods/risc0-verifier) that was executed in RiscZero v2.2 zkVM.

[^4]: CVMs on GCP must provide the TPM AK Certificate Chain to the Workload Verifier to extract the TPM AK Key.

[^5]: Upon spawning a TDX CVM instance on GCP, a UUID is generated and stored in `rtmr3` of the TD module as `sha384(0x00 || sha384(UUID))`. Computing `sha384` onchain without a precompile is expensive.
