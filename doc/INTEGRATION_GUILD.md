### Integration Guide

#### Installation

To integrate WorkloadVerifier into your project, install it as a Foundry dependency:

```shell
forge install automata-network/tee-workload-measurement
```

#### Import Remapping

Add the following remapping to your `foundry.toml` file:

```toml
[profile.default]
remappings = [
    "@automata-network/tee-workload-measurement/=lib/tee-workload-measurement/contracts/src/"
]
```

#### Basic Usage

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
        // - check whether the measurement hash matches an application-specific golden measurement hash
        // - validate TPM extra data, e.g. replay protection
    }
}
```

### API Reference

All methods shown below can be called to perform verification on your CVM workload. The choice of each method is dependent on the type of return data you may need for post verification.

#### `verifyAttestation`

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

#### `verifyAttestationAndGetMeasurement`

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

#### `verifyAttestationAndGetMeasurementHash`

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

### Golden Measurement

The golden measurement or its hash is a proof of workload integrity that represents:

- **Workload Identity**: A unique fingerprint of the verified CVM workload
- **Integrity Assurance**: Cryptographic proof that the workload hasn't been tampered with
- **Compliance Evidence**: Verifiable proof for regulatory or security requirements