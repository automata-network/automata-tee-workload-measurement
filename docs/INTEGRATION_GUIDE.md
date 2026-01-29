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
    "@automata-network/tee-workload-measurement/=lib/automata-tee-workload-measurement/src/"
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
        bytes32 measurementHash = workloadVerifier.verifyAttestationAndGetMeasurementHash(
            teeType,
            teeReportType,
            cloudType,
            teeAttestationReport,
            workloadCollaterals
        );

        // Validate against golden measurement
        require(measurementHash == goldenMeasurementHash, "Invalid measurement");

        emit WorkloadVerified(measurementHash);

        // Execute privileged operation
        _executePrivilegedOperation();
    }

    function _executePrivilegedOperation() internal {
        // Your application logic
    }
}
```

## CVM Registry Integration

### Basic Integration

Use the CVMRegistry for identity management and message verification. Applications should inherit from `CVMSignature` base contract for built-in domain separation and signature verification.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ICVMRegistry, CVMIdentity} from "@automata-network/tee-workload-measurement/interfaces/ICVMRegistry.sol";
import {CVMSignature} from "@automata-network/tee-workload-measurement/usecases/bases/CVMSignature.sol";

contract MyCVMApp is CVMSignature {
    ICVMRegistry public immutable cvmRegistry;
    mapping(bytes32 => bool) public allowedMeasurements;

    // App-specific replay protection
    mapping(bytes32 => mapping(bytes32 => bool)) public usedNonces;

    event ActionExecuted(bytes32 indexed cvmIdentityHash);

    constructor(address _cvmRegistry, address _p256Verifier) {
        cvmRegistry = ICVMRegistry(_cvmRegistry);
        _writeP256VerifyAddress(_p256Verifier);
    }

    function addAllowedMeasurement(bytes32 measurementHash) external {
        // Add access control as needed
        allowedMeasurements[measurementHash] = true;
    }

    function executeAction(
        bytes32 cvmIdentityHash,
        bytes calldata userData,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        // 1. Check CVM is registered and valid
        require(cvmRegistry.hasRegistered(cvmIdentityHash), "CVM not registered");
        require(cvmRegistry.checkCvmValidity(cvmIdentityHash), "CVM expired");

        // 2. Validate measurement against golden measurement
        bytes32 measurementHash = cvmRegistry.getMeasurementHash(cvmIdentityHash);
        require(allowedMeasurements[measurementHash], "Invalid measurement");

        // 3. App-specific replay protection
        require(!usedNonces[cvmIdentityHash][nonce], "Nonce already used");
        usedNonces[cvmIdentityHash][nonce] = true;

        // 4. Construct domain-separated message using CVMSignature helper
        bytes memory message = _generateMessage(abi.encodePacked(nonce, userData));

        // 5. Verify signature using CVMSignature helper
        CVMIdentity memory cvmIdentity = cvmRegistry.getCvmIdentity(cvmIdentityHash);
        require(_verifySignature(cvmIdentity, signature, message), "Invalid signature");

        emit ActionExecuted(cvmIdentityHash);

        // 6. Execute action
        _executeAction(userData);
    }

    function _executeAction(bytes calldata userData) internal {
        // Your application logic
    }
}
```

**Key Integration Points:**

1. **Inherit from `CVMSignature`**: Provides `_generateMessage()`, `_generateMessageWithCustomPrefix()`, and `_verifySignature()` helpers
2. **Use `checkCvmValidity()`**: Single validity check instead of separate TEE/TPM checks
3. **Implement replay protection**: The registry does NOT provide nonce-based replay protection for apps - you must implement your own
4. **Domain separation**: Use `_generateMessage()` for standard messages or `_generateMessageWithCustomPrefix()` for custom message types
5. **Signature verification**: `_verifySignature()` handles both RSA and ECDSA signatures automatically based on the CVM identity's signature algorithm

