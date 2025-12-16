# TEE Workload Measurement Integration Guide

This guide provides step-by-step instructions for integrating the TEE Workload Measurement contracts into your application.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Install as Foundry Dependency](#1-install-as-foundry-dependency)
  - [2. Configure Remappings](#2-configure-remappings)
  - [3. Verify Installation](#3-verify-installation)
- [Workload Verifier Integration](#workload-verifier-integration)
  - [Basic Integration](#basic-integration)
- [CVM Registry Integration](#cvm-registry-integration)
  - [Basic Integration](#basic-integration-1)

---

## Prerequisites

Before integrating, ensure you have:

- **Foundry** installed ([Installation Guide](https://book.getfoundry.sh/getting-started/installation))
- Access to a **CVM with TEE** (Intel TDX or AMD SEV-SNP) on Azure or GCP
- The [**CVM Agent**](https://github.com/automata-network/cvm-agent) running in your CVM

---

## Installation

### 1. Install as Foundry Dependency

```bash
forge install automata-network/automata-tee-workload-measurement
```

### 2. Configure Remappings

Add to your `foundry.toml`:

```toml
[profile.default]
remappings = [
    "@automata-network/tee-workload-measurement/=lib/automata-tee-workload-measurement/contracts/src/"
]
```

### 3. Verify Installation

```bash
forge build
```

---

## Workload Verifier Integration

### Basic Integration

Use the WorkloadVerifier for direct verification of CVM workload integrity.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IWorkloadVerifier, WorkloadCollaterals} from "@automata-network/tee-workload-measurement/interfaces/IWorkloadVerifier.sol";
import {TEEType, TeeReportType, CloudType} from "@automata-network/tee-workload-measurement/lib/LibTEE.sol";

contract MyWorkloadVerifier {
    IWorkloadVerifier public immutable workloadVerifier;
    bytes32 public goldenMeasurementHash;

    event WorkloadVerified(bytes32 measurementHash);

    constructor(address _workloadVerifier, bytes32 _goldenMeasurementHash) {
        workloadVerifier = IWorkloadVerifier(_workloadVerifier);
        goldenMeasurementHash = _goldenMeasurementHash;
    }

    function verifyWorkload(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata workloadCollaterals
    ) external payable {
        // Verify attestation and get measurement hash
        (
            bytes memory teeOutput,
            bytes32 measurementHash,
            bytes memory tpmExtraData
        ) = workloadVerifier.verifyAttestationAndGetMeasurementHash(
            teeType,
            teeReportType,
            cloudType,
            teeAttestationReport,
            workloadCollaterals
        );

        // Validate against golden measurement
        require(measurementHash == goldenMeasurementHash, "Invalid measurement");

        // Validate TPM extra data (application-specific)
        _validateTpmExtraData(tpmExtraData);

        emit WorkloadVerified(measurementHash);

        // Execute privileged operation
        _executePrivilegedOperation();
    }

    function _validateTpmExtraData(bytes memory tpmExtraData) internal {
        // Your validation logic (e.g., nonce, replay protection)
    }

    function _executePrivilegedOperation() internal {
        // Your application logic
    }
}
```

## CVM Registry Integration

### Basic Integration

Use the CVMRegistry for identity management and message verification.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICVMRegistry} from "@automata-network/tee-workload-measurement/interfaces/ICVMRegistry.sol";
import {Pubkey} from "@automata-network/tee-workload-measurement/types/Pubkey.sol";

contract MyCVMApp {
    ICVMRegistry public immutable cvmRegistry;
    mapping(bytes32 => bool) public allowedMeasurements;

    event ActionExecuted(bytes32 indexed cvmIdentityHash);

    constructor(address _cvmRegistry) {
        cvmRegistry = ICVMRegistry(_cvmRegistry);
    }

    function addAllowedMeasurement(bytes32 measurementHash) external {
        // Add access control as needed
        allowedMeasurements[measurementHash] = true;
    }

    function executeAction(
        bytes32 cvmIdentityHash,
        bytes calldata message,
        bytes calldata signature
    ) external {
        // 1. Check CVM is registered
        require(cvmRegistry.hasRegistered(cvmIdentityHash), "CVM not registered");

        // 2. Check freshness
        require(cvmRegistry.checkTEEValidity(cvmIdentityHash), "TEE expired");
        require(cvmRegistry.checkTPMValidity(cvmIdentityHash), "TPM expired");

        // 3. Validate measurement
        bytes32 measurementHash = cvmRegistry.getMeasurementHash(cvmIdentityHash);
        require(allowedMeasurements[measurementHash], "Invalid measurement");

        // 4. Verify signature
        bytes32 messageHash = _constructMessageHash(message);
        _verifySignature(cvmIdentityHash, messageHash, signature);

        emit ActionExecuted(cvmIdentityHash);

        // 5. Execute action
        _executeAction(message);
    }

    function _constructMessageHash(bytes calldata message) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "CVM_WORKLOAD_USER_MESSAGE",
            uint256(block.chainid),
            address(this),
            message
        ));
    }

    function _verifySignature(
        bytes32 cvmIdentityHash,
        bytes32 messageHash,
        bytes calldata signature
    ) internal view {
        Pubkey memory identity = cvmRegistry.getCvmIdentity(cvmIdentityHash);

        // Get P256 verifier for ECDSA signatures
        address p256Verifier = identity.sigScheme == 0x0018
            ? cvmRegistry.tpmAttestation().p256()
            : address(0);

        require(
            identity.verifySignature(
                abi.encodePacked(messageHash),
                signature,
                p256Verifier
            ),
            "Invalid signature"
        );
    }

    function _executeAction(bytes calldata message) internal {
        // Your application logic
    }
}
```

