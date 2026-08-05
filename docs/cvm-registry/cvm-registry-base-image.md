# BaseImageRegistry -- Detailed Analysis

**File**: `src/BaseImageRegistry.sol`
**Interface**: `src/interfaces/registries/IBaseImageRegistry.sol`
**Role**: Manages OS/platform measurement policies. PCR 0 through 19 is the
usual convention, not a contract-enforced range.

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
        ├── invariants: PcrSpec[]     (platform baseline by convention)
        ├── attributes: Attribute[]   (key-value metadata)
        └── MeasurementVariant[] (e.g. "n2d-standard-2", "c3-standard-4")
              ├── name: string
              ├── overridePcrs: PcrSpec[]  (indices the profile leaves unpinned; disjoint from invariants)
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
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 baseImageId)
```

- Registers new base image with hierarchical profiles and variants
- `measurementVariants` is a 2D array: `measurementVariants[i]` maps to `platformProfiles[i]`
- Computes owner fingerprint, verifies signature over `sha256(abi.encode(BASEIMAGE_REGISTER_MSG, chainid, address(this), opExpiresAt, spec, platformProfiles, measurementVariants))`
- Registration allowed when: `registrationRestricted()` is false, or the owner is whitelisted
- Validates: signature expiry, array length match, PCR order, attribute uniqueness
- Emits: `BaseImageRegistered`, `PlatformProfileRegistered`, `MeasurementVariantRegistered`

### `deactivateBaseImage`
```solidity
function deactivateBaseImage(
    bytes32 baseImageId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true` (soft delete)
- Requires owner signature over `sha256(abi.encode(BASEIMAGE_DEACTIVATE_MSG, chainid, address(this), opExpiresAt, baseImageId))`
- Emits: `BaseImageDeactivated`

### `addPlatformVariants`
```solidity
function addPlatformVariants(
    bytes32 baseImageId,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Append-only for new metadata; lenient about resubmitted profile metadata:
  - New profile ids → stored with their `invariants` + `attributes`; emits `PlatformProfileRegistered`.
  - Existing profile ids → submitted `invariants` and `attributes` are silently dropped (§14.2). The stored profile metadata is immutable post-registration; only the variant set under that profile can grow. Callers can pass the full PlatformProfile struct from their config without having to clear the metadata fields first.
  - New variant ids → stored with their `overridePcrs` + `attributes`; emits `MeasurementVariantRegistered`.
  - Existing variant ids → reverts `MeasurementVariantAlreadyExists(variantId)`.
  - Every new profile and variant may contain fully validated custom and reserved attributes. A variant attribute replaces the matching stored profile attribute for sessions that select that variant.
  - Adding a variant does not change an existing policy branch. The new variant id is immutable after it is stored. The verified TEE report and workload policy still gate every new session that selects it.
- Gated by the same whitelist check as `registerBaseImage`: allowed when `registrationRestricted()` is false, or the owner is whitelisted. An appended variant is a new selectable policy branch that may declare its own reserved TEE attributes, so an owner removed from the whitelist cannot widen a base image they registered while whitelisted.

#### Scope of the append-only guarantee

Append-only immutability is **per variant id**, not per base image. A session
records its `measurementVariantId`, and that branch's stored `overridePcrs` and
attributes never change. It does not follow that the set of policies reachable
under a given `baseImageId` is fixed: the owner may append a further variant
that declares different reserved TEE attributes, and a registrant is free to
select it. A variant with an empty `overridePcrs` adds no measurement
constraint of its own.

Two limits bound what an appended branch can do. The workload leg is evaluated
independently and resolves to the `AmdSnpSecurityPolicyRegistry` default
whenever the workload states nothing, so a base-image-side relaxation alone
cannot go below that default. And the whitelist gate above applies to the
append itself.

A relying party that needs a fixed policy must therefore pin the
`measurementVariantId` (or the `platformProfileId` plus its variant set), not
the `baseImageId` alone. See `cvm-registry-amd-snp-policy.md` for how the two
legs combine.
- Requires owner signature over `sha256(abi.encode(BASEIMAGE_UPDATE_MSG, chainid, address(this), opExpiresAt, baseImageId, platformProfiles, measurementVariants))`.
- Emits: `BaseImageUpdated`, `PlatformProfileRegistered` (only for newly-created profiles), `MeasurementVariantRegistered` (per new variant).

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getBaseImage(baseImageId)` | `BaseImageSpec` | Reverts if not found |
| `getPlatformProfile(platformProfileId)` | `PlatformProfile` | Reverts if not found |
| `getMeasurementVariant(variantId)` | `MeasurementVariant` | Reverts if not found |
| `getVariant(baseImageId, platformProfileId, variantId)` | `(BaseImageSpec, PlatformProfile, MeasurementVariant)` | All three in one call. Enforces parent-child binding: the platform profile MUST belong to the base image and the variant MUST belong to the platform profile — otherwise reverts `HierarchyMismatch(baseImageId, platformProfileId, variantId)`. |
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
| `registrationRestricted()` | True when only whitelisted owners may register or update |

## Errors

| Error | Condition |
|---|---|
| `BaseImageAlreadyExists(bytes32 baseImageId)` | Duplicate registration attempt |
| `BaseImageNotFound(bytes32 baseImageId)` | ID doesn't exist |
| `BaseImageNotActive(bytes32 baseImageId)` | Image is revoked |
| `PlatformProfileNotFound(bytes32 platformProfileId)` | Profile ID doesn't exist |
| `MeasurementVariantNotFound(bytes32 variantId)` | Variant ID doesn't exist |
| `MeasurementVariantAlreadyExists(bytes32 variantId)` | `addPlatformVariants` / `registerBaseImage` is append-only; can't re-register a variantId |
| `PlatformProfileAlreadyExists(bytes32 profileId)` | `registerBaseImage` got two input profiles with the same `name` (would silently overwrite + duplicate the id in `platformProfileIds`). `addPlatformVariants` does NOT raise this — it tolerates resubmitted profile metadata silently. |
| `HierarchyMismatch(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)` | A profile or variant does not belong to the supplied parent. |
| `ArrayLengthMismatch(uint256 platformProfilesLen, uint256 measurementVariantsLen)` | `platformProfiles.length != measurementVariants.length` |
| `InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint)` | Signature verification failed |
| `Unauthorized(bytes32 actualOwner, bytes32 expectedOwner)` | Signer does not own the base image |
| `SignatureExpired(uint64 opExpiresAt, uint64 nowTs)` | `block.timestamp > opExpiresAt` |
| `InvalidPcrOrder(uint8 prevIndex, uint8 thisIndex)` | PCR specs are not strictly ascending by index |
| `PcrIndexOutOfRange(uint8 pcrIndex)` | PCR index >= 24 |
| `EmptyPcrComparison(uint8 pcrIndex)` | A PCR rule has an empty opaque `comparison` blob |
| `DuplicateAttributeKey(bytes32 key)` | Repeated key in attributes array |
| `InvalidTeeAttributeValue(bytes32 key, bytes32 actualValue)` | A reserved Boolean is invalid, the Intel TDX TCB mask omits `ok` or contains a non-configurable bit, or an AMD SEV-SNP packed value has an invalid layout |
| `NotWhitelisted(bytes32 ownerFingerprint)` | Owner fingerprint not in whitelist |

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

1. **PCR shape and ordering**: PCR rules must be sorted ascending by `pcrIndex`, every `pcrIndex` must be `< 24`, and `comparison` must not be empty. `BaseImageRegistry` does not decode comparison types.
2. **Attribute uniqueness**: No duplicate keys within an attributes array (enforced by `_validateAttributes`, uses an in-memory hash table)
3. **Reserved Boolean TEE attribute values**: Intel TDX debug, AMD SEV-SNP debug, and AMD SEV-SNP `MIGRATE_MA` accept only the canonical Boolean encodings. Missing means `false`.
4. **Intel TDX TCB mask**: The mask must include `ok` and may contain only bits in `0x33f`. Missing means `ok` only.
5. **AMD SEV-SNP packed policy**: `tcb.minimum` requires four valid 64-bit lanes. `platform-info.policy` requires valid, non-overlapping set and clear masks. A missing measurement-variant value falls back to the platform-profile value. If both are missing, verification uses the active exact-CPUID `AmdSnpSecurityPolicyRegistry` default.
6. **Measurement-variant attributes**: Custom and reserved attributes use the same value and duplicate-key validation in profiles and variants. A variant may declare any valid value for the selected hardware branch.
7. **Append-only policy**: `addPlatformVariants` ignores submitted metadata for an existing profile, accepts fully validated attributes for a new profile or variant, and rejects an existing variant id.
8. **Parallel array invariant**: `platformProfiles.length == measurementVariants.length`
9. **Signature expiry**: `block.timestamp <= opExpiresAt`
10. **Owner match**: Signer fingerprint must match stored owner for updates/deactivation
11. **Registration gating**: If `registrationRestricted()` and owner not in `_whitelist`, revert `NotWhitelisted`. False = open registration. Applies to `registerBaseImage` and `addPlatformVariants` alike, because both publish policy that sessions can select.

## Initialization

Contract starts **paused** (`_pause()` called in `initialize`). Owner must either unpause or whitelist fingerprints before registration is possible.

## Internal Helpers

- `_checkRegistrationAllowed(ownerFingerprint)` -- Reverts NotWhitelisted if paused AND not whitelisted
- `_validatePcrSpecsSorted(PcrSpec[])` -- Checks ascending order, index range (< 24), exact-one `STATIC` cardinality, and non-empty `DYNAMIC_*` cardinality
- `_validateAttributes(Attribute[])` -- Validates reserved verified TEE attribute values and checks attribute-key uniqueness

## Implementation Nuance

`getVariant(baseImageId, platformProfileId, variantId)` enforces parent-child binding in addition to existence. By construction every child ID embeds its parent in its keccak preimage:

- `platformProfileId = keccak256(PLATFORM_PROFILE_DOMAIN ‖ baseImageId ‖ profile.name)`
- `variantId = keccak256(PLATFORM_VARIANT_DOMAIN ‖ platformProfileId ‖ variant.name)`

After the existence checks pass, `getVariant` recomputes each expected child ID from the **caller-provided parent** and the **stored child name** and reverts `HierarchyMismatch(baseImageId, platformProfileId, variantId)` if either equality fails. By collision resistance, a match proves the child was registered under that exact parent.

This invariant is load-bearing: `SessionRegistry._lookupPolicy` reads `(platformProfile, variant)` via `getVariant` and uses them as the PCR policy for the session being registered. Without the hierarchy check a caller could pair their target `baseImageId` with an unrelated platform profile / variant from a weaker base image and bypass PCR policy enforcement.
