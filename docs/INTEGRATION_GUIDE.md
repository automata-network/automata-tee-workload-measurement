# Integration Guide

This guide explains how to integrate with the CVM Registry System. There are two integration paths:

1. **Rust Client SDK** — For CVM workloads and off-chain services that need to register sessions, rotate keys, or relay transactions
2. **Solidity Smart Contract** — For on-chain applications that need to verify CVM session signatures or query session state

---

## Prerequisites

- Contract addresses (see [Deployment](../README.md#deployment) in the README)
- For Rust SDK: Rust toolchain installed
- For Solidity: [Foundry](https://book.getfoundry.sh/getting-started/installation) installed

---

## Rust Client SDK

The Rust SDK provides type-safe bindings for all registry operations. It lives in `crates/automata-tee-workload-measurement/`.

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
automata-tee-workload-measurement = { git = "https://github.com/automata-network/automata-tee-workload-measurement", package = "automata-tee-workload-measurement" }
```

### Initializing the Client

```rust
use automata_tee_workload_measurement::{WorkloadMeasurement, WorkloadMeasurementConfig};

let cfg = WorkloadMeasurementConfig {
    rpc_url: "https://your-hoodi-rpc.example.com".to_string(),
    relay_key: Some(your_private_key),
    session_registry_address: "0xD1860020870ffEd23a644d0CD4CA9E7b3Ff53D6c".parse()?,
};

let client = WorkloadMeasurement::new(cfg).await?;
```

The `WorkloadMeasurement` client automatically discovers `BaseImageRegistry` and `WorkloadRegistry` addresses from the `SessionRegistry` on-chain. You can access individual registries via:

```rust
let session_reg = client.session_registry();
let base_image_reg = client.base_image_registry();
let workload_reg = client.workload_registry();
```

### Computing IDs

Use `AppRef` to compute deterministic IDs for base images and workloads:

```rust
use automata_tee_workload_measurement::types::AppRef;

let base_image_ref = AppRef::new("ubuntu-confidential-24.04", "1.0.0");
let workload_ref = AppRef::new("my-workload", "1.0.0");

// IDs are computed as keccak256(abi.encode(DOMAIN, name, version))
let base_image_id = base_image_ref.id("CVM_BASEIMAGE_V1");
let workload_id = workload_ref.id("CVM_WORKLOAD_V1");
```

### Registering a Session

```rust
let response = client.register_session(RegisterSessionRequest {
    signer: &signer,                // PrivateKeySigner for the owner
    evidence,                       // AttestationEvidence from CVM agent
    workload_ref,                   // AppRef for the workload
    base_image_ref,                 // AppRef for the base image
    platform_profile_id,            // bytes32 platform profile ID
    variant_id,                     // bytes32 measurement variant ID
    expire_offset_secs: 3600,       // signature validity window
}).await?;

println!("Session ID: {}", response.session_id);
println!("TX Hash: {}", response.tx_hash);
```

The SDK handles:
- Session ID computation from attestation evidence
- Owner signature generation with correct domain separation
- Transaction submission and event parsing

### Rotating a Session

```rust
let response = client.rotate_session(RotateSessionRequest {
    signer: &signer,
    old_session_id,
    tee_report_bytes_hash,
    rotation_evidence,
    expire_offset_secs: 3600,
}).await?;

println!("New Session ID: {}", response.new_session_id);
```

---

## Solidity Smart Contract

For on-chain applications that need to verify CVM session signatures or enforce workload-based access control.

### Installation

```bash
forge install automata-network/automata-tee-workload-measurement
```

Add to your `foundry.toml`:

```toml
[profile.default]
remappings = [
    "@automata-network/tee-workload-measurement/=lib/automata-tee-workload-measurement/src/"
]
```

Verify:

```bash
forge build
```

### Verifying Session Signatures

The primary integration point — verify that a message was signed by an active CVM session:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ISessionRegistry} from
    "@automata-network/tee-workload-measurement/interfaces/registries/ISessionRegistry.sol";
import {CVMSession, PublicIdentity} from
    "@automata-network/tee-workload-measurement/types/Common.sol";

contract MyCVMApp {
    ISessionRegistry public immutable sessionRegistry;

    constructor(address _sessionRegistry) {
        sessionRegistry = ISessionRegistry(_sessionRegistry);
    }

    function executeAction(
        bytes32 sessionId,
        PublicIdentity calldata sessionKey,
        bytes32 message,
        bytes calldata signature,
        bytes calldata userData
    ) external {
        // 1. Verify the message was signed by an active session's key
        require(
            sessionRegistry.verifySessionSignature(sessionId, sessionKey, message, signature),
            "Invalid session signature"
        );

        // 2. (Optional) Enforce workload or base image policies
        CVMSession memory session = sessionRegistry.getSession(sessionId);
        require(session.workloadId == EXPECTED_WORKLOAD_ID, "Wrong workload");

        // 3. Execute privileged logic
        _handleAction(userData);
    }

    function _handleAction(bytes calldata) internal {
        // Your application logic
    }
}
```

> **Note:** The `sessionKey` (`PublicIdentity`) is emitted in the `AttestationKeysRevealed` event during session registration. Your off-chain service should index this event and pass the full key when calling `verifySessionSignature`.

### Querying Session State

```solidity
// Check if session is still valid
bool active = sessionRegistry.isSessionActive(sessionId);

// Get full session data
CVMSession memory session = sessionRegistry.getSession(sessionId);

// Check session owner
bytes32 owner = sessionRegistry.getSessionOwner(sessionId);

// Check if expired
bool expired = sessionRegistry.isSessionExpired(sessionId);
```

### Querying Registry Data

```solidity
import {IBaseImageRegistry} from
    "@automata-network/tee-workload-measurement/interfaces/registries/IBaseImageRegistry.sol";
import {IWorkloadRegistry} from
    "@automata-network/tee-workload-measurement/interfaces/registries/IWorkloadRegistry.sol";
import {BaseImageSpec, PlatformProfile, MeasurementVariant, WorkloadSpec} from
    "@automata-network/tee-workload-measurement/types/Common.sol";

// Get base image info
BaseImageSpec memory spec = baseImageRegistry.getBaseImage(baseImageId);

// Get all three tiers in one call
(BaseImageSpec memory img, PlatformProfile memory profile, MeasurementVariant memory variant) =
    baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId);

// Get workload info
WorkloadSpec memory workload = workloadRegistry.getWorkload(workloadId);

// Check if a base image is allowed for a workload
bool allowed = workloadRegistry.isBaseImageAllowed(workloadId, baseImageId);
```

---

## Quick Reference

| Task | Rust SDK | Solidity |
| --- | --- | --- |
| Register session | `WorkloadMeasurement::register_session()` | `ISessionRegistry.registerSession()` |
| Rotate session | `WorkloadMeasurement::rotate_session()` | `ISessionRegistry.rotateSession()` |
| Verify session signature | — | `ISessionRegistry.verifySessionSignature()` |
| Check session active | — | `ISessionRegistry.isSessionActive()` |
| Query session | — | `ISessionRegistry.getSession()` |
| Compute base image ID | `AppRef::id("CVM_BASEIMAGE_V1")` | `keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))` |
| Compute workload ID | `AppRef::id("CVM_WORKLOAD_V1")` | `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))` |
