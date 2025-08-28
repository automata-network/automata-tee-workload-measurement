# Automata TEE Workload Measurement (EVM Smart Contract)

This document describes the EVM implementation for onchain verification and measurement of the workload of a Confidential VM (CVM) instance hosted on cloud service providers.

TEE Onchain Workload Measurement implementation can be found [`WorkloadVerifier.sol`](./src/WorkloadVerifier.sol), which is dependent on:

1. [Automata DCAP Attestation](https://github.com/automata-network/automata-dcap-attestation/tree/main/evm) to verify Intel TDX quotes
2. [Automata SEV-SNP Attestation](https://github.com/automata-network/amd-sev-snp-attestation-sdk/tree/main/zk/contracts) to verify AMD SEV SNP attestation reports.
3. [Automata TPM Attestation](https://github.com/automata-network/automata-tpm-attestation) to verify TPM quote, checking PCR measurements and extract the user provided data.

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
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata workloadCollaterals
    ) external payable {
        bytes memory teeOutput;
        bytes32 measurementHash;
        bytes memory tpmExtraData;
        (teeOutput, measurementHash, tpmExtraData) 
            = workloadVerifier.verifyAttestationAndGetMeasurementHash(
                teeType,
                teeReportType,
                cloudType,
                teeAttestationReport,
                workloadCollaterals
            );
        
        // application developers can perform the following at this point:
        // - validate the teeOutput, such as checking the TCB Status, extracting the TEE Report
        // - check whether the meeasurement hash matches an application-specific golden measurement hash
        // - validate TPM extra data, e.g. replay protection
    }
}
```

---

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

#### `Measurement`

```solidity
/**
 * @dev must provide either TDX or SNP Reports. 
 * (both cannot simultaneously contain value or empty)
 */
struct Measurement {
    Pcr[] pcrs;           // PCR values and/or selected event logs that a workload must produce
    TdxMeasurement tdx;   // TD 1.0 Report Body
    SnpMeasurement snp;   // AMD SEV SNP Report Body
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

---

## API Reference

All methods shown below can be called to perform verification on your CVM workload. The choice of each method is dependent on the type of return data you may need for post verification.

### `verifyAttestation`

```solidity
function verifyAttestation(
    TEEType teeType,
    TeeReportType teeReportType,
    CloudType cloudType,
    bytes calldata _teeAttestationReport,
    WorkloadCollaterals calldata _workloadReport
)
    external
    payable
    returns (bytes memory teeOutput, TEEVerifiedData memory teeVerifiedData, bytes memory tpmExtraData);
```

This method returns data that can be trusted, given all values have been validated by the TEE.

Use this method if you need the following:
- TEE Measurements, which in turn can be converted to the Workload final measurement values by calling the `getMeasurement()` method.
- The Report ID value that binds the TPM to the TEE.
- The TPM Attestation Key used to sign the TPM Quote.

Alternatively, you may opt for calling either the `verifyAttestationAndGetMeasurement` or `verifyAttestationAndGetMeasurementHash` method if your use case simply require the Workload measurement values. Saving gas cost from memory reads.

**Parameters:**
- `teeType`: The TEE technology used (`IntelTdx` or `AmdSevSnp`)
- `teeReportType`: The report verification method (`Solidity` for onchain or `ZkRiscZero`/`ZkSp1` for ZK proofs)
- `cloudType`: The cloud provider (`Azure` or `Gcp`)
- `_teeAttestationReport`: The TEE attestation report data
- `_workloadReport`: Additional verification data (see WorkloadCollaterals below)

**Returns:**
- `teeOutput`: The output returned by the TEE Verifier contract
- `TEEVerifiedData`: A struct consists of trusted values that are validated by the TEE
- `tpmExtraData`: User provided data

### `verifyAttestationAndGetMeasurement`

```solidity
function verifyAttestationAndGetMeasurement(
    TEEType teeType,
    TeeReportType teeReportType,
    CloudType cloudType,
    bytes calldata _teeAttestationReport,
    WorkloadCollaterals calldata _workloadReport
) external payable returns (bytes memory teeOutput, Measurement memory measurement, bytes memory tpmExtraData);
```

**Returns:**
- `teeOutput`: The output returned by the TEE Verifier contract
- `Measurement`: The final Measurement object
- `tpmExtraData`: User provided data

### `verifyAttestationAndGetMeasurementHash`

```solidity
function verifyAttestationAndGetMeasurementHash(
    TEEType teeType,
    TeeReportType teeReportType,
    CloudType cloudType,
    bytes calldata _teeAttestationReport,
    WorkloadCollaterals calldata _workloadReport
) external payable returns (bytes memory teeOutput, bytes32 measurementHash, bytes memory tpmExtraData);
```

**Returns:**
- `teeOutput`: The output returned by the TEE Verifier contract
- `measurementHash`: The measurement hash representing the verified workload
- `tpmExtraData`: User provided data

---

## Golden Measurement

The golden measurement or its hash is a proof of workload integrity that represents:

- **Workload Identity**: A unique fingerprint of the verified CVM workload
- **Integrity Assurance**: Cryptographic proof that the workload hasn't been tampered with
- **Compliance Evidence**: Verifiable proof for regulatory or security requirements

**Use Cases:**

1. **Integrity Verification**: Compare the returned hash against expected measurement values to ensure workload authenticity
2. **Trust Chains**: Store the hash onchain to build verifiable trust relationships between different workloads
3. **Compliance Tracking**: Use the hash as evidence for audit trails and regulatory compliance
4. **Access Control**: Gate access to sensitive operations based on verified workload measurements
5. **Reputation Systems**: Build reputation scores based on consistently verified workload behavior

## Gas Benchmark

The table below shows our initial finding on gas costs to measure CVMs with various TEEs hosted on Azure and GCP.

|  | TEE Report Verification Gas Cost | AK Pubkey Verification Gas Cost | TPM Signature Verification Gas Cost | PCR Measurement Check Gas Cost | Report ID Binding Check Gas Cost | Measurement Computation Gas Cost |
| --- | --- | --- | --- | --- | --- | --- |
| Azure TDX | ~5M[^1] gas (Onchain DCAP) | 50k[^2] gas | 42k gas (RSA) | 14k gas | 3k gas | 23k gas |
| Azure AMD-SEV-SNP | 240k[^3] gas (RiscZero Groth16) | 50k[^2] gas | 42k gas (RSA) | 14k gas | 3k gas | 23k gas |
| GCP TDX | ~5M[^1] gas (Onchain DCAP) | 397k[^1][^4] gas | 339k[^1] gas (secp256r1) | 16k gas | 385k[^5] gas | 82k gas |
| GCP AMD-SEV-SNP | 240k[^3] gas (RiscZero Groth16) | 397k[^1][^4] gas | 339k[^1] gas (secp256r1) | 16k gas | 5k gas | 82k gas |

### Remark:

[^1]: secp256r1 ECDSA is executed with the [daimo-p256](https://github.com/daimo-eth/p256-verifier) contract. The gas cost is about 330k per signature. EVM Chains that implement [RIP 7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) can significantly reduce cost to only 3450 gas per signature.

[^2]: TEE Attestation Report generated by CVMs on Azure already contains the hash of the TPM Attestation Key, hence confirming its association with the TPM quote. This step merely parses `azure_var.json` to extract the TPM Attestation public key. This step will fail if the users did not provide `azure_var.json` as part of the workload collateral.

[^3]: AMD-SEV-SNP attestation report currently can only be verified onchain using SNARK proofs. The proof provided in our test is generated by a [RiscZero Guest Program](https://github.com/automata-network/amd-sev-snp-attestation-sdk/tree/v2/crates/risc0-methods/risc0-verifier) that was executed in RiscZero v2.2 zkVM.

[^4]: CVMs on GCP must provide the TPM AK Certificate Chain to the Workload Verifier to extract the TPM AK Key. Upon successful verification of the chain, the TPM Attestation contract caches intermediate certificates, which could reduce gas costs for future verifications.

[^5]: Upon spawning a TDX CVM instance on GCP, a UUID is generated and stored in `rtmr3` of the TD module as `sha384(0x00 || sha384(UUID))`. Computing `sha384` onchain without a precompile is expensive.
