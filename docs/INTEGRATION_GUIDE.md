# Integration Guide

This guide explains how to integrate with the CVM Registry System. There are two integration paths:

1. **Rust Client SDK** — For CVM workloads and off-chain services that need to register sessions, rotate keys, or relay transactions
2. **Solidity Smart Contract** — For on-chain applications that need to verify CVM session signatures or query session state

---

## Prerequisites

- A verified `SessionRegistry` address and its immutable dependency graph
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
    session_registry_address: "0x1111111111111111111111111111111111111111".parse()?,
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
    evidence,
    workload_id,
    base_image_id,
    platform_profile_id,
    variant_id,
    op_expires_at,
    owner_identity,
    owner_signature,
}).await?;

println!("Session ID: {}", response.session_id);
println!("TX Hash: {}", response.tx_hash);
```

`register_session` accepts a pre-signed owner operation. The caller constructs
the exact domain-separated owner message and supplies `owner_signature`. The
SDK submits the transaction and parses the result.

### Rotating a Session

```rust
let response = client.rotate_key(RotateKeyRequest {
    old_session_id,
    tee_report_bytes_hash,
    rotation_evidence,
    op_expires_at,
    owner_identity,
    owner_signature,
}).await?;

println!("New Session ID: {}", response.new_session_id);
```

`rotate_key` does not extend `sessionExpiresAt`. Use `renew_session` with fresh
attestation and predecessor TPM authorization to extend the lifecycle. Use
`recover_session` with fresh attestation and owner authorization when the
predecessor TPM key is unavailable.

### Reserved TEE attribute helpers

The SDK exposes the six exact reserved names and keys through
`automata_tee_workload_measurement::types`. Use `tee_attribute_key` and
`tee_attribute_name` for the exact mapping. Use
`tee_attribute_boolean_value`, `tdx_tcb_status_bit`,
`tdx_tcb_status_mask`, and `tdx_tcb_status_names` for the canonical Boolean
and Intel TDX TCB encodings. AMD SEV-SNP TCB and `PLATFORM_INFO` policies are
already packed `bytes32` values; do not hash their hexadecimal text.

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

// Get all three tiers in one call. Reverts HierarchyMismatch unless the
// supplied platformProfileId was registered under baseImageId and variantId
// was registered under platformProfileId.
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
| Rotate keys without extending expiry | `WorkloadMeasurement::rotate_key()` | `ISessionRegistry.rotateKey()` |
| Renew with fresh attestation | `WorkloadMeasurement::renew_session()` | `ISessionRegistry.renewSession()` |
| Recover with fresh attestation | `WorkloadMeasurement::recover_session()` | `ISessionRegistry.recoverSession()` |
| Verify session signature | — | `ISessionRegistry.verifySessionSignature()` |
| Check session active | — | `ISessionRegistry.isSessionActive()` |
| Query session | — | `ISessionRegistry.getSession()` |
| Compute base image ID | `AppRef::id("CVM_BASEIMAGE_V1")` | `keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))` |
| Compute workload ID | `AppRef::id("CVM_WORKLOAD_V1")` | `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))` |
