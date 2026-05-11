# BaseImageRegistry -- Detailed Analysis

**File**: `src/BaseImageRegistry.sol` (544 lines)
**Interface**: `src/interfaces/registries/IBaseImageRegistry.sol`
**Role**: Manages OS/platform measurement policies (PCR 0-19)

## Inheritance

```
IBaseImageRegistry
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
| `_baseImages` | `mapping(bytes32 => BaseImageSpecStorage)` | Core base image data |
| `_platformProfiles` | `mapping(bytes32 => PlatformProfileStorage)` | Per-platform configs |
| `_variants` | `mapping(bytes32 => MeasurementVariantStorage)` | Machine-specific overrides |
| `_whitelist` | `mapping(bytes32 => bool)` | Owner fingerprint whitelist |
| `__gap` | `uint256[46]` | Storage gap for upgrades |

## Storage Structs

```solidity
struct BaseImageSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;           // owner fingerprint
    BaseImageSpec spec;      // name, version, uri
    bytes32[] platformProfileIds;
}

struct PlatformProfileStorage {
    bool exists;
    PlatformProfile platformProfile;  // name, invariants[], attributes[]
    bytes32[] variantIds;
}

struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant measurementVariant;  // name, overridePcrs[], attributes[]
}
```

## Data Model Hierarchy

```
BaseImage (e.g. "automata-linux v0.1.6")
  ├── spec: { name, version, uri }
  ├── owner: bytes32 fingerprint
  └── PlatformProfile[] (e.g. "gcp-tdx", "azure-snp")
        ├── name: string
        ├── invariants: PcrSpec[]     (PCR 0-19 baseline)
        ├── attributes: Attribute[]   (key-value metadata)
        └── MeasurementVariant[] (e.g. "n2d-standard-2", "c3-standard-4")
              ├── name: string
              ├── overridePcrs: PcrSpec[]  (replaces invariants at matching pcrIndex)
              └── attributes: Attribute[] (replaces profile attrs at matching key)
```

## ID Derivation

All use `abi.encode` (NOT `encodePacked`). NOTE: No ownerFingerprint in baseImageId.

```
baseImageId = keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))
platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))
variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variantName))
```

## Public Functions

### `registerBaseImage`
```solidity
function registerBaseImage(
    BaseImageSpec calldata spec,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 baseImageId)
```

- Registers new base image with hierarchical profiles and variants
- `measurementVariants` is a 2D array: `measurementVariants[i]` maps to `platformProfiles[i]`
- Computes owner fingerprint, verifies signature over `sha256(abi.encode(BASEIMAGE_REGISTER_MSG, chainid, address(this), expireAt, spec, platformProfiles, measurementVariants))`
- Registration allowed when: unpaused OR owner is whitelisted (uses `_checkRegistrationAllowed`, NOT `whenNotPaused` modifier)
- Validates: signature expiry, array length match, PCR order, attribute uniqueness
- Emits: `BaseImageRegistered`, `PlatformProfileRegistered`, `MeasurementVariantRegistered`

### `deactivateBaseImage`
```solidity
function deactivateBaseImage(
    bytes32 baseImageId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true` (soft delete)
- Requires owner signature over `sha256(abi.encode(BASEIMAGE_DEACTIVATE_MSG, chainid, address(this), expireAt, baseImageId))`
- Emits: `BaseImageDeactivated`

### `addPlatformVariants`
```solidity
function addPlatformVariants(
    bytes32 baseImageId,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Adds or upserts platform profiles and variants to existing base image
- Profile upsert: replaces `invariants` and `attributes`, preserves existing `variantIds` (appends new ones)
- Variant upsert: replaces `overridePcrs` and `attributes`
- Requires owner signature over `sha256(abi.encode(BASEIMAGE_UPDATE_MSG, chainid, address(this), expireAt, baseImageId, platformProfiles, measurementVariants))`
- Emits: `BaseImageUpdated`, `PlatformProfileRegistered`, `MeasurementVariantRegistered`

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getBaseImage(baseImageId)` | `BaseImageSpec` | Reverts if not found |
| `getPlatformProfile(platformProfileId)` | `PlatformProfile` | Reverts if not found |
| `getMeasurementVariant(variantId)` | `MeasurementVariant` | Reverts if not found |
| `getVariant(baseImageId, platformProfileId, variantId)` | `(BaseImageSpec, PlatformProfile, MeasurementVariant)` | All three in one call |
| `getBaseImageOwner(baseImageId)` | `bytes32` | Owner fingerprint |
| `isBaseImageRevoked(baseImageId)` | `bool` | Revocation status |
| `hasVariant(variantId)` | `bool` | Existence check |

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
| `BaseImageAlreadyExists` | Duplicate registration attempt |
| `BaseImageNotFound` | ID doesn't exist |
| `BaseImageNotActive` | Image is revoked |
| `PlatformProfileNotFound` | Profile ID doesn't exist |
| `MeasurementVariantNotFound` | Variant ID doesn't exist |
| `ArrayLengthMismatch` | `platformProfiles.length != measurementVariants.length` |
| `InvalidSignature` | Signature verification failed |
| `Unauthorized` | Signer != owner |
| `SignatureExpired` | `block.timestamp > expireAt` |
| `InvalidPcrOrder` | PCR specs not sorted ascending by index |
| `PcrIndexOutOfRange` | PCR index > 23 |
| `DuplicateAttributeKey` | Repeated key in attributes array |
| `NotWhitelisted` | Owner fingerprint not in whitelist |

## Events

| Event | Fields |
|---|---|
| `BaseImageRegistered` | `baseImageId, owner, name, version` |
| `BaseImageDeactivated` | `baseImageId, owner` |
| `PlatformProfileRegistered` | `baseImageId, platformProfileId, name` |
| `MeasurementVariantRegistered` | `platformProfileId, variantId, name` |
| `BaseImageUpdated` | `baseImageId, owner` |
| `WhitelistAdded` | `fingerprint` |
| `WhitelistRemoved` | `fingerprint` |

## Validation Rules

1. **PCR ordering**: `pcrSpecs` must be sorted ascending by `pcrIndex` (enforced by `_validatePcrSpecsSorted`)
2. **Attribute uniqueness**: No duplicate keys within an attributes array (enforced by `_validateUniqueAttributeKeys`, uses in-memory hash table)
3. **Parallel array invariant**: `platformProfiles.length == measurementVariants.length`
4. **Signature expiry**: `block.timestamp <= expireAt`
5. **Owner match**: Signer fingerprint must match stored owner for updates/deactivation
6. **Registration gating**: If `paused()` and owner not in `_whitelist`, revert `NotWhitelisted`. Unpaused = open registration.

## Initialization

Contract starts **paused** (`_pause()` called in `initialize`). Owner must either unpause or whitelist fingerprints before registration is possible.

## Internal Helpers

- `_checkRegistrationAllowed(ownerFingerprint)` -- Reverts NotWhitelisted if paused AND not whitelisted
- `_validatePcrSpecsSorted(PcrSpec[])` -- Checks ascending order and index range (< 24)
- `_validateUniqueAttributeKeys(Attribute[])` -- Hash-table-based uniqueness check for attribute keys
