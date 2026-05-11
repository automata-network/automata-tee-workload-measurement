# Developer Guide

Technical documentation for the CVM Registry System — a three-tier registry architecture for on-chain verification and management of Confidential VM workloads.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Key Concepts](#key-concepts)
- [BaseImageRegistry](#baseimageregistry)
- [WorkloadRegistry](#workloadregistry)
- [SessionRegistry](#sessionregistry)
- [9-Step Session Verification](#9-step-session-verification)
- [PCR Verification Types](#pcr-verification-types)
- [Session Lifecycle](#session-lifecycle)
- [Data Structures Reference](#data-structures-reference)

---

## Architecture Overview

The system is composed of six contract groups with strict separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Session Registry                         │
│           (attestation verification, session lifecycle)          │
├──────────┬──────────────┬──────────────┬───────────┬────────────┤
│ Base     │  Workload    │  Verifier    │  Key      │ Signature  │
│ Image    │  Registry    │  Contracts   │  Resolver │ Verifier   │
│ Registry │              │              │           │            │
│ (platform│ (application │ (TEE + TPM   │ (public   │ (PublicId  │
│  policy) │  policy)     │  validation) │  key      │  signature │
│          │              │              │  store)   │  validation│
└──────────┴──────────────┴──────────────┴───────────┴────────────┘
```

- **BaseImageRegistry** — Defines platform images and their expected PCR measurement specifications. Managed by base image publishers.
- **WorkloadRegistry** — Defines application-level policies including base image access control, attribute requirements, and PCR constraints. Managed by workload developers.
- **SessionRegistry** — Orchestrates the full attestation verification workflow, creates on-chain session identities, and manages session lifecycle.
- **TeeVerifier** — Stateless dispatcher for TEE attestation reports. Routes to DCAP (Intel TDX) or SNP (AMD SEV-SNP) verifiers. Supports ZK proof backends (RiscZero, SP1).
- **SignatureVerifier** — Validates cryptographic signatures from any `PublicIdentity` key. Supports RS256, ES256 (P-256), and ES256K (secp256k1).
- **KeyResolver** — Maps public key fingerprints to full `PublicIdentity` representations. Serves as an on-chain identity directory.

### Contract Inheritance

**SessionRegistry:**
```
SessionRegistry
├── TpmVerifier (TPM Quote + TPM Certify verification)
├── AkCollateralVerifier (AK certificate chain validation)
├── OwnableUpgradeable
└── UUPSUpgradeable
```

**BaseImageRegistry / WorkloadRegistry:**
```
{BaseImage|Workload}Registry
├── OwnableUpgradeable
├── PausableUpgradeable (whitelist enforcement)
└── UUPSUpgradeable
```

---

## Key Concepts

### Ownership Model

Registry ownership is **orthogonal to EVM accounts**. Owners are identified by `PublicIdentity` keys, which may use any supported algorithm:

| Algorithm | ID | Description |
| --- | --- | --- |
| RS256 | 1 | RSA PKCS#1 v1.5 with SHA-256 |
| ES256 | 2 | ECDSA P-256 with SHA-256 |
| ES256K | 3 | ECDSA secp256k1 with SHA-256 |

All mutating registry operations (registration, deactivation, revocation) require a cryptographic signature from the owner's private key, verified on-chain via `SignatureVerifier`. This decouples resource ownership from Ethereum addresses, allowing TEE-managed keys to own registry entries.

### Key Fingerprints

Every `PublicIdentity` has a unique 32-byte fingerprint used as its identifier throughout the system:

```
fingerprint = keccak256(abi.encode(KEY_DOMAIN, typeId, key))
```

where `KEY_DOMAIN = keccak256("KEY_RESOLVER_V1")`. Fingerprints are used for owner identity, session key binding, nonce tracking, and access control.

### Domain Separation

All identifiers and signatures use domain-separated hashing to prevent cross-context collisions:

| Constant | Value | Purpose |
| --- | --- | --- |
| `KEY_DOMAIN` | `keccak256("KEY_RESOLVER_V1")` | Key fingerprint computation |
| `SESSION_DOMAIN` | `keccak256("CVM_SESSION_V1")` | Session ID computation |
| `DELEGATION_DOMAIN` | `keccak256("CVM_SESSION_KEY_DELEGATION")` | Session key delegation |
| `ROTATION_DOMAIN` | `keccak256("CVM_SESSION_KEY_ROTATION")` | Session rotation authorization |
| `BASEIMAGE_DOMAIN` | `keccak256("CVM_BASEIMAGE_V1")` | Base image ID computation |
| `WORKLOAD_DOMAIN` | `keccak256("CVM_WORKLOAD_V1")` | Workload ID computation |
| `PLATFORM_PROFILE_DOMAIN` | `keccak256("CVM_PLATFORM_PROFILE_V1")` | Platform profile ID computation |
| `PLATFORM_VARIANT_DOMAIN` | `keccak256("CVM_PLATFORM_VARIANT_V1")` | Measurement variant ID computation |
| `SESSION_NONCE_DOMAIN` | `keccak256("CVM_SESSION_REG_NONCE_V1")` | TPM quote nonce binding |

Operation message separators (for signed requests):

| Constant | Value |
| --- | --- |
| `SESSION_REGISTER_MSG` | `keccak256("CVM_MSG_SESSION_REGISTER_V1")` |
| `SESSION_REVOKE_MSG` | `keccak256("CVM_MSG_SESSION_REVOKE_V1")` |
| `SESSION_ROTATE_MSG` | `keccak256("CVM_MSG_SESSION_ROTATE_V1")` |
| `BASEIMAGE_REGISTER_MSG` | `keccak256("CVM_MSG_BASEIMAGE_REGISTER_V1")` |
| `BASEIMAGE_DEACTIVATE_MSG` | `keccak256("CVM_MSG_BASEIMAGE_DEACTIVATE_V1")` |
| `BASEIMAGE_UPDATE_MSG` | `keccak256("CVM_MSG_BASEIMAGE_UPDATE_V1")` |
| `WORKLOAD_REGISTER_MSG` | `keccak256("CVM_MSG_WORKLOAD_REGISTER_V1")` |
| `WORKLOAD_DEACTIVATE_MSG` | `keccak256("CVM_MSG_WORKLOAD_DEACTIVATE_V1")` |

### Whitelist Mode

Both `BaseImageRegistry` and `WorkloadRegistry` support a whitelist mode for permissioned access during initial rollout. When paused, only owner fingerprints that have been explicitly whitelisted can register entries. This is toggled via the admin-controlled `pause()` / `unpause()` mechanism.

---

## BaseImageRegistry

Manages **operating system and platform measurement policies** (PCR 0-19). Operated by privileged base image publishers (e.g., OS vendors, platform operators).

### Three-Level Hierarchy

```
BaseImage (name, version, URI)
└── PlatformProfile (cloud provider + TEE config)
    ├── Invariant PCRs (constant across all machine types)
    ├── Platform attributes (cloud, tee type, region, etc.)
    └── MeasurementVariant (machine-type-specific)
        ├── Override PCRs (machine-specific measurements)
        └── Machine attributes (cpu, gpu, memory, etc.)
```

- **BaseImage** — The OS environment itself (kernel, bootloader, CVM agent). Identified by name + version.
- **PlatformProfile** — A specific cloud provider and TEE configuration (e.g., "gcp-tdx", "azure-snp"). Contains PCR invariants that are constant across all machine types on that platform.
- **MeasurementVariant** — Machine-type-specific PCR overrides (e.g., "n2d-standard-16" on GCP). Some PCR values change depending on CPU architecture, GPU presence, or memory configuration.

### ID Computation

```
baseImageId      = keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))
platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))
variantId        = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, profileId, variantName))
```

### Key Operations

**Registration:**
```solidity
function registerBaseImage(
    BaseImageSpec calldata spec,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 baseImageId);
```

Registers a base image with all its platform profiles and measurement variants in a single call. The parallel array invariant: `platformProfiles[i]` corresponds to `measurementVariants[i][]`.

**Adding Variants:**
```solidity
function addPlatformVariants(
    bytes32 baseImageId,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;
```

Additive/upsert semantics — new profiles and variants are added, existing ones (matching name → matching ID) are overwritten. Unmentioned entries remain untouched.

**View Functions:**
- `getBaseImage(baseImageId)` → `BaseImageSpec`
- `getPlatformProfile(platformProfileId)` → `PlatformProfile`
- `getMeasurementVariant(variantId)` → `MeasurementVariant`
- `getVariant(baseImageId, platformProfileId, variantId)` → all three specs in one call
- `getBaseImageOwner(baseImageId)` → owner fingerprint
- `isBaseImageRevoked(baseImageId)` → revocation status

---

## WorkloadRegistry

Manages **application-level measurement policies** (PCR 20-23). Operated by workload developers who publish containerized applications.

### WorkloadSpec

A workload specification defines:

- **name / version** — Human-readable identifier (e.g., "ml-training-service", "2.1.0")
- **ttl** — Session time-to-live in seconds (0 = default 30 days)
- **baseImageMode** — Access control for which base images can run this workload:
  - `ANY` — No restrictions
  - `WHITELIST` — Only base images in `baseImageIds` are allowed
  - `BLACKLIST` — Base images in `baseImageIds` are blocked
- **requirements** — Attribute requirements that platform attributes must satisfy (all must pass)
- **pcrs** — PCR specifications for workload measurements (typically PCR 20-23)

### ID Computation

```
workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
```

### Key Operations

**Registration:**
```solidity
function registerWorkload(
    WorkloadSpec calldata spec,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 workloadId);
```

**View Functions:**
- `getWorkload(workloadId)` → `WorkloadSpec`
- `getWorkloadOwner(workloadId)` → owner fingerprint
- `isWorkloadRevoked(workloadId)` → revocation status
- `isBaseImageAllowed(workloadId, baseImageId)` → access control check

---

## SessionRegistry

The **central orchestrator** that ties everything together. It verifies attestation evidence against policies from both registries, creates on-chain session identities, and manages their lifecycle.

### Dependencies (Immutable)

The SessionRegistry holds immutable references to:
- `ITeeVerifier` — TEE attestation verification
- `ISignatureVerifier` — Cryptographic signature verification
- `IBaseImageRegistry` — Platform policy lookup
- `IWorkloadRegistry` — Application policy lookup
- `ITpmAttestation` — TPM quote and certificate verification

### Key Operations

```solidity
// Register a session after 9-step attestation verification
function registerSession(
    AttestationEvidence calldata evidence,
    bytes32 workloadId, bytes32 baseImageId,
    bytes32 platformProfileId, bytes32 variantId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 sessionId);

// Revoke a session (owner only)
function revokeSession(
    bytes32 sessionId, uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

// Rotate session keys without full TEE re-attestation
function rotateSession(
    bytes32 oldSessionId, bytes32 teeReportBytesHash,
    SessionRotationEvidence calldata rotationEvidence,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId);

// Verify a message signed by a session key
function verifySessionSignature(
    bytes32 sessionId, PublicIdentity calldata sessionKey,
    bytes32 message, bytes calldata signature
) external view returns (bool valid);
```

### View Functions

- `getSession(sessionId)` → `CVMSession`
- `getSessionOwner(sessionId)` → owner fingerprint
- `isSessionActive(sessionId)` → true if not revoked and not expired
- `isSessionExpired(sessionId)` → true if past TTL
- `getNonce(ownerFingerprint)` → current nonce for replay protection

---

## 9-Step Session Verification

When `registerSession()` is called, the system performs a comprehensive 9-step verification:

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Policy Lookup                                              │
│  Fetch workload, base image, platform profile, and variant specs    │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 2: TEE Attestation Verification                               │
│  Verify Intel TDX quote or AMD SEV-SNP report                      │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 3: AK Collateral Verification + TEE-AK Binding               │
│  Validate Attestation Key and bind TEE to vTPM                      │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 4: TPM Quote Verification                                     │
│  Verify TPM quote signature, extract PCRs, validate nonce           │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 5: TPM Certify Verification                                   │
│  Verify TPM signing key is certified by AK                          │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 6: Session ID + Session Key Delegation                        │
│  Compute session ID, verify TPM key delegates to session key        │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 7: Base Image PCR Policy Evaluation                           │
│  Match PCRs 0-14 against platform invariants + variant overrides    │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 8: Workload PCR + Attribute Policy Evaluation                 │
│  Match PCRs 20-23 against workload specs, validate attributes       │
├─────────────────────────────────────────────────────────────────────┤
│  STEP 9: Owner Signature Verification                               │
│  Verify owner signature, increment nonce, store session             │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 1: Policy Lookup

Retrieves all policy data from the registries:
- `WorkloadSpec` from WorkloadRegistry
- `BaseImageSpec`, `PlatformProfile`, `MeasurementVariant` from BaseImageRegistry

Validates:
- Workload is active (not revoked)
- Base image is active (not revoked)
- Base image is allowed by the workload's access control policy (`isBaseImageAllowed`)

### Step 2: TEE Attestation Verification

Dispatches to `TeeVerifier`, which routes to the appropriate backend:
- **Intel TDX** → `IDcapAttestation` contract (on-chain DCAP verification)
- **AMD SEV-SNP** → `ISnpAttestation` contract

Supports three verification backends: `Solidity` (on-chain), `ZkRiscZero`, `ZkSuccinct`.

Returns a `TeeVerificationResult` containing the validated report body and extracted report data.

### Step 3: AK Collateral Verification + TEE-AK Binding

Verifies the Attestation Key (AK) and its binding to the TEE instance:

- **Azure**: AK public key extracted from JSON collateral. Binding verified by checking that `reportData[0:32] == sha256(akCollateral)`.
- **GCP (TDX)**: AK extracted from X.509 certificate chain. Binding verified via RTMR3 containing `sha384(bytes48(0) || bytes32(0) || UUID)`, where UUID is from `reportData[520:536]`. Also computes `expectedPcr15 = sha256(bytes32(0) || bytes16(0) || UUID)`. The 16-byte UUID is left-padded with zeros to fill each bank's register width (no intermediate hash).
- **GCP (SNP)**: AK from X.509 chain. Binding via `report_id` at SNP report offset `0x140`. Computes `expectedPcr15 = sha256(0x00 || report_id)`.

### Step 4: TPM Quote Verification

Verifies the TPM Quote report:
- Validates the AK signature over the TPM2B_ATTEST structure
- Checks nonce binding: `extraData == keccak256(SESSION_NONCE_DOMAIN, ownerFingerprint, currentNonce)`
- Extracts measured PCR values from the quote

This step ensures the PCR measurements are fresh and tied to this specific registration request.

### Step 5: TPM Certify Verification

Verifies the TPM2_Certify report:
- Validates the AK signature over the certify structure
- Extracts the certified TPM signing key
- Checks TPMA_OBJECT attributes to ensure the key was created by the TPM with appropriate security properties (fixedTPM, fixedParent, sensitiveDataOrigin, sign)

### Step 6: Session ID + Session Key Delegation

Computes the session ID:
```
sessionId = keccak256(abi.encode(SESSION_DOMAIN, keccak256(tpmSignature), keccak256(teeReport.data)))
```

Verifies session key delegation — the TPM signing key authorizes the session key:
```
delegationMessage = keccak256(abi.encode(
    DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint
))
```

The TPM signing key's signature over this message proves the session key is authorized with full context binding.

### Step 7: Base Image PCR Policy Evaluation

Evaluates platform measurement policies:
1. Merges PlatformProfile invariant PCRs with MeasurementVariant override PCRs (variant overrides platform at matching indices)
2. Evaluates effective PCR specs against measured values from the TPM quote
3. For GCP: additionally validates that measured PCR 15 matches the expected binding value computed in Step 3

### Step 8: Workload PCR + Attribute Policy Evaluation

Evaluates application measurement policies:
1. Evaluates WorkloadSpec PCR specs (typically PCR 20-23) against measured values
2. Merges platform attributes with variant attributes (variant overrides platform at matching keys)
3. Validates all WorkloadSpec attribute requirements against the merged attributes

### Step 9: Owner Signature Verification

Verifies the owner's authorization:
```
message = sha256(abi.encode(SESSION_REGISTER_MSG, chainId, address(this), expireAt, sessionId))
```

- Signature verified via `SignatureVerifier` against `ownerIdentity`
- Owner nonce incremented for replay protection
- Session created with TTL from WorkloadSpec (default 30 days if 0)
- Events emitted: `SessionRegistered`, `AttestationKeysRevealed`

### Chain of Trust

The 9-step process establishes this chain of trust:

```
TEE Hardware (Intel TDX / AMD SEV-SNP)
    ↓  TEE attestation report (Step 2)
Attestation Key (AK)
    ↓  AK collateral + TEE-AK binding (Step 3)
TPM Quote
    ↓  AK verifies quote signature (Step 4)
TPM Signing Key
    ↓  AK certifies key via TPM2_Certify (Step 5)
Session Key
    ↓  TPM signing key delegates to session key (Step 6)
On-Chain Session Identity
    ↓  PCR policies validated (Steps 7-8)
    ↓  Owner authorizes (Step 9)
Active CVMSession
```

---

## PCR Verification Types

Three strategies for matching measured PCR values against policy specifications:

### STATIC — Exact Value Match

```
matchData[0] must exactly equal the PCR final value
```

Use for deterministic measurements that never change (e.g., firmware hash, bootloader hash). The PCR value is computed as a sequential hash chain of events, producing a single final value that must match exactly.

### DYNAMIC_SUBSET — Event Subset

```
All measured PCR event hashes must be members of matchData (any order)
```

Use for configurations where a known set of events can occur in any combination. For example, a platform that allows different optional kernel modules — each module produces an event, and all events must be from the allowed set, but not all allowed events need to be present.

### DYNAMIC_SUBSEQUENCE — Ordered Event Sequence

```
matchData must appear as an ordered subsequence within the measured event hashes
```

Use for boot sequences where event order matters but additional events may be interspersed. The required events must appear in the correct order, though other events can appear between them.

---

## Session Lifecycle

### Registration

Full 9-step attestation verification as described above. On success, a `CVMSession` is created on-chain with:
- Key fingerprints for the entire chain of trust (AK, TPM signing key, session key)
- Context identifiers (base image, workload, platform profile, variant)
- Lifecycle timestamps (registeredAt, expiresAt)

### Rotation

Replace TPM signing key and session key **without** full TEE re-attestation:

1. Validate old session exists, is not revoked, and is not expired
2. Verify new TPM quote with AK (re-validates PCRs with fresh nonce)
3. Verify new TPM signing key certified by same AK
4. Old TPM signing key signs rotation authorization:
   ```
   keccak256(abi.encode(ROTATION_DOMAIN, oldSessionId, newTpmKeyFingerprint, newSessionKeyFingerprint, teeReportBytesHash))
   ```
5. Compute new session ID from new TPM signature
6. Verify new session key delegation
7. Re-evaluate PCR and attribute policies
8. Verify owner signature under `SESSION_ROTATE_MSG`
9. Revoke old session, create new session

### Revocation

Owner-initiated session invalidation:
- Owner signs message under `SESSION_REVOKE_MSG` with session ID
- Session marked as revoked (permanently, cannot be un-revoked)
- Only the session owner can revoke

### Session Signature Verification

Downstream contracts call `verifySessionSignature()` to authenticate messages from CVM workloads:

```solidity
bool valid = sessionRegistry.verifySessionSignature(sessionId, sessionKey, message, signature);
```

This checks:
1. Session exists
2. Session is active (not revoked, not expired)
3. `sessionKey` fingerprint matches the stored `sessionKeyFingerprint`
4. Signature over `message` is valid for `sessionKey`

> **Note:** The `sessionKey` (full `PublicIdentity`) is available from the `AttestationKeysRevealed` event emitted during registration. Callers must cache or pass it since only fingerprints are stored on-chain.

---

## Data Structures Reference

### PublicIdentity

```solidity
struct PublicIdentity {
    uint8 typeId;  // Algorithm ID (0=NULL, 1=RS256, 2=ES256, 3=ES256K)
    bytes key;     // Public key bytes in algorithm-specific encoding
}
```

### PcrSpec

```solidity
struct PcrSpec {
    uint8 pcrIndex;           // PCR index (0-23)
    PcrVerifyType verifyType; // STATIC, DYNAMIC_SUBSET, or DYNAMIC_SUBSEQUENCE
    bytes32[] matchData;      // Interpretation depends on verifyType
}
```

### CVMSession

```solidity
struct CVMSession {
    bytes32 akPubKeyFingerprint;        // Attestation Key fingerprint
    bytes32 tpmSigningKeyFingerprint;   // TPM signing key fingerprint
    bytes32 sessionKeyFingerprint;      // Operational session key fingerprint
    bytes32 baseImageId;                // Associated base image
    bytes32 workloadId;                 // Associated workload
    bytes32 platformProfileId;          // Platform profile
    bytes32 measurementVariantId;       // Measurement variant
    uint64 registeredAt;                // Registration timestamp
    uint64 expiresAt;                   // Expiration timestamp
}
```

### BaseImageSpec / PlatformProfile / MeasurementVariant

```solidity
struct BaseImageSpec {
    string name;     // e.g., "ubuntu-confidential-22.04"
    string version;  // e.g., "1.2.3"
    string uri;      // Metadata URI (IPFS, registry URL)
}

struct PlatformProfile {
    string name;              // e.g., "gcp-tdx"
    PcrSpec[] invariants;     // PCRs constant across machine types
    Attribute[] attributes;   // Platform-wide metadata
}

struct MeasurementVariant {
    string name;                // e.g., "n2d-standard-16"
    PcrSpec[] overridePcrs;     // Machine-specific PCR overrides
    Attribute[] attributes;     // Machine-specific metadata
}
```

### WorkloadSpec

```solidity
struct WorkloadSpec {
    string name;                              // e.g., "ml-training-service"
    string version;                           // e.g., "2.1.0"
    uint64 ttl;                               // Session TTL in seconds (0 = default 30 days)
    AccessMode baseImageMode;                 // ANY, BLACKLIST, or WHITELIST
    bytes32[] baseImageIds;                   // Base images for access control
    AttributeRequirement[] requirements;      // Attribute requirements (all must pass)
    PcrSpec[] pcrs;                           // Workload PCR specs (PCR 20-23)
}
```

### AttestationEvidence

```solidity
struct AttestationEvidence {
    TeeReport teeReport;                    // TEE attestation report
    TpmReport tpmQuoteReport;               // TPM Quote (PCR measurements)
    TpmReport tpmCertifyReport;             // TPM Certify (key certification)
    AkPubCollateral akPubCollateral;        // Attestation Key collateral
    bytes sessionKeySignature;              // Delegation: TPM key signs session key
    PublicIdentity sessionKey;              // Session public key
}
```

### SessionRotationEvidence

```solidity
struct SessionRotationEvidence {
    TpmReport tpmQuoteReport;               // New TPM Quote
    TpmReport tpmCertifyReport;             // New TPM Certify
    bytes sessionKeySignature;              // New delegation signature
    PublicIdentity sessionKey;              // New session key
    bytes rotationSignature;                // Old TPM key authorizes rotation
    PublicIdentity oldTpmSigningKey;        // Old TPM signing key (for verification)
    PublicIdentity akPub;                   // Attestation Key
}
```
