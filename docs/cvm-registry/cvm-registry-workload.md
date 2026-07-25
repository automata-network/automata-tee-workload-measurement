# WorkloadRegistry -- Detailed Analysis

**File**: `src/WorkloadRegistry.sol` (312 lines)
**Interface**: `src/interfaces/registries/IWorkloadRegistry.sol`
**Role**: Manages application measurement policies (PCR 20-23)

## Inheritance

```
IWorkloadRegistry
OwnableUpgradeable
PausableUpgradeable
UUPSUpgradeable
```

## Immutables

| Variable | Type | Purpose |
|---|---|---|
| `signatureVerifier` | `ISignatureVerifier` | Signature verification dependency |

## Storage

| Variable | Type | Purpose |
|---|---|---|
| `_workloads` | `mapping(bytes32 => WorkloadSpecStorage)` | Workload specifications |
| `_baseImageSet` | `mapping(bytes32 => mapping(bytes32 => bool))` | Base image allowlist/blocklist lookup |
| `_whitelist` | `mapping(bytes32 => bool)` | Owner fingerprint whitelist |
| `__gap` | `uint256[47]` | Storage gap for upgrades |

## Storage Struct

```solidity
struct WorkloadSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;              // owner fingerprint
    WorkloadSpec workloadSpec;  // full specification
}
```

## Data Model

```solidity
struct WorkloadSpec {
    string name;
    string version;
    uint64 ttl;                          // session TTL in seconds (0 ⇒ SessionRegistry default of 30 days)
    AccessMode baseImageMode;            // ANY | WHITELIST | BLACKLIST
    bytes32[] baseImageIds;              // list for whitelist/blacklist
    AttributeRequirement[] requirements; // constraints on platform attributes
    PcrSpec[] pcrs;                      // PCR 20-23 specs
}

struct AttributeRequirement {
    bytes32 key;
    bytes32[] allowedValues;  // empty = any value accepted (just require key exists)
}

enum AccessMode {
    ANY,        // all base images allowed
    BLACKLIST,  // listed base images blocked
    WHITELIST   // only listed base images allowed
}
```

## ID Derivation

NOTE: No ownerFingerprint in workload ID.
```
workloadId = keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))
```

## Public Functions

### `registerWorkload`
```solidity
function registerWorkload(
    WorkloadSpec calldata spec,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 workloadId)
```

- Registers workload with full policy specification
- `spec.ttl` is consumed later by `SessionRegistry`; `ttl == 0` means "use `DEFAULT_CVM_TTL` (30 days)" (`src/SessionRegistry.sol:273-274`)
- Computes owner fingerprint, verifies signature over `sha256(abi.encode(WORKLOAD_REGISTER_MSG, chainid, address(this), expireAt, spec))`
- Registration allowed when: unpaused OR owner is whitelisted (uses `_checkRegistrationAllowed`, NOT `whenNotPaused`)
- Populates `_baseImageSet` mapping for efficient `isBaseImageAllowed` lookups
- Validates: signature expiry, PCR order, requirement key uniqueness
- Emits: `WorkloadRegistered`

### `deactivateWorkload`
```solidity
function deactivateWorkload(
    bytes32 workloadId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true` (soft delete)
- Requires owner signature over `sha256(abi.encode(WORKLOAD_DEACTIVATE_MSG, chainid, address(this), expireAt, workloadId))`
- Emits: `WorkloadDeactivated`

### `isBaseImageAllowed`
```solidity
function isBaseImageAllowed(
    bytes32 workloadId,
    bytes32 baseImageId
) external view returns (bool)
```

Logic:
- `AccessMode.ANY` → always `true`
- `AccessMode.WHITELIST` → `true` only if `_baseImageSet[workloadId][baseImageId] == true`
- `AccessMode.BLACKLIST` → `true` only if `_baseImageSet[workloadId][baseImageId] == false`

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getWorkload(workloadId)` | `WorkloadSpec` | Reverts if not found |
| `getWorkloadOwner(workloadId)` | `bytes32` | Owner fingerprint |
| `isWorkloadRevoked(workloadId)` | `bool` | Revocation status |

### Admin Functions (owner-only)

| Function | Purpose |
|---|---|
| `addToWhitelist(bytes32[])` | Add fingerprints to registration whitelist |
| `removeFromWhitelist(bytes32)` | Remove fingerprint from whitelist |
| `isWhitelisted(bytes32)` | Check whitelist status |
| `pause()` | Pause registration |
| `unpause()` | Unpause registration |

## Errors

| Error | Condition |
|---|---|
| `WorkloadAlreadyExists(bytes32 workloadId)` | Duplicate registration |
| `WorkloadNotFound(bytes32 workloadId)` | ID doesn't exist |
| `WorkloadNotActive(bytes32 workloadId)` | Workload is revoked |
| `InvalidSignature()` | Signature verification failed |
| `Unauthorized()` | Signer != owner |
| `SignatureExpired()` | `block.timestamp > expireAt` |
| `InvalidPcrOrder()` | PCR specs not sorted ascending |
| `PcrIndexOutOfRange(uint8 pcrIndex)` | PCR index >= 24 |
| `EmptyMatchData(uint8 pcrIndex)` | `DYNAMIC_SUBSET` / `DYNAMIC_SUBSEQUENCE` spec with zero-length `matchData` |
| `DuplicateRequirementKey(bytes32 key)` | Repeated key in requirements array |
| `InvalidTeeAttributeRequirementLength(bytes32 key, uint256 actualLength)` | Reserved verified TEE requirement has the wrong number of values |
| `InvalidTeeAttributeRequirementValue(bytes32 key, bytes32 actualValue)` | Reserved verified TEE requirement is not exactly `[false]` or `[false, true]` |
| `NotWhitelisted(bytes32 ownerFingerprint)` | Owner fingerprint not whitelisted |

## Events

| Event | Fields |
|---|---|
| `WorkloadRegistered` | `workloadId, owner, name, version` |
| `WorkloadDeactivated` | `workloadId, owner` |
| `WhitelistAdded` | `fingerprint` |
| `WhitelistRemoved` | `fingerprint` |

## Validation Rules

1. **PCR ordering**: `pcrSpecs` must be sorted ascending by `pcrIndex`, and every `pcrIndex` must be `< 24`
2. **Requirement key uniqueness**: No duplicate keys in `requirements` array (hash-table check via `_validateRequirements`)
3. **Reserved TEE requirements**: The three exact reserved keys accept only `[bytes32(0)]` or `[bytes32(0), bytes32(uint256(1))]`. Missing means `[false]`.
4. **Signature expiry**: `block.timestamp <= expireAt`
5. **Registration gating**: If `paused()` and owner not in `_whitelist`, revert `NotWhitelisted`. Unpaused = open registration.

## Initialization

Contract starts **paused** (`_pause()` called in `initialize`).

## Comparison with BaseImageRegistry

| Aspect | BaseImageRegistry | WorkloadRegistry |
|---|---|---|
| PCR range | 0-19 (platform) | 20-23 (application) |
| Hierarchy | BaseImage → Profile → Variant | Flat (single WorkloadSpec) |
| Access control | N/A | Base image allow/blocklist |
| Attributes | Key-value pairs (provided) | Requirements (demanded) |
| TTL | N/A | Defined per workload |
| Complexity | Higher (3-level hierarchy) | Simpler (flat) |
