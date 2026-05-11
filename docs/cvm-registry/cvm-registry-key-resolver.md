# KeyResolver -- Detailed Analysis

**File**: `src/KeyResolver.sol` (102 lines)
**Interface**: `src/interfaces/registries/IKeyResolver.sol`
**Role**: Global public key fingerprint directory

## Inheritance

```
IKeyResolver
OwnableUpgradeable
UUPSUpgradeable
```

## Storage

| Variable | Type | Purpose |
|---|---|---|
| `_identities` | `mapping(bytes32 => PublicIdentity)` | Fingerprint → identity mapping |
| `__gap` | `uint256[49]` | Storage gap for upgrades |

## Fingerprint Computation

```
fingerprint = keccak256(KEY_DOMAIN || typeId || key)
```

Where `KEY_DOMAIN = keccak256("KEY_RESOLVER_V1")`.

Existence check: `_identities[fingerprint].typeId != ALGO_ID_NULL` (typeId 0 = not registered).

## Functions

### `registerIdentity`
```solidity
function registerIdentity(PublicIdentity calldata identity) external returns (bytes32 fingerprint)
```
- Computes fingerprint from identity
- Validates identity is not null (`typeId != ALGO_ID_NULL && key.length > 0`)
- **Idempotent**: if already registered, returns fingerprint without error
- Stores `PublicIdentity` at fingerprint key
- Returns fingerprint

### `getIdentity`
```solidity
function getIdentity(bytes32 fingerprint) external view returns (PublicIdentity memory)
```
- Returns stored identity for fingerprint
- Reverts with `IdentityNotFound(fingerprint)` if not registered

### `hasIdentity`
```solidity
function hasIdentity(bytes32 fingerprint) external view returns (bool)
```
- Returns `_identities[fingerprint].typeId != ALGO_ID_NULL`

### `computeFingerprint`
```solidity
function computeFingerprint(PublicIdentity calldata identity) external pure returns (bytes32)
```
- Pure function: computes fingerprint without registration
- Calls `LibKey.computeKeyFingerprint(identity)`

## Errors

| Error | Condition |
|---|---|
| `IdentityNotFound(bytes32 fingerprint)` | `getIdentity` called with unregistered fingerprint |
| `InvalidIdentity()` | `typeId == ALGO_ID_NULL` or `key.length == 0` |

## Design Notes

- **No access control on registration**: Anyone can register any public key. This is safe because fingerprints are deterministic -- registering someone else's key just makes it discoverable, doesn't grant any privileges.
- **Idempotent**: Re-registering the same key is a no-op (no revert, no event re-emission).
- **Used by**: Other contracts can use KeyResolver to look up full public keys from fingerprints. However, the main registries (BaseImage, Workload, Session) do NOT require prior KeyResolver registration -- they compute fingerprints inline from provided `PublicIdentity` values.
- **UUPS upgradeable**: Has `_authorizeUpgrade` restricted to owner.

## Relationship to Other Contracts

KeyResolver is somewhat standalone. The main registries compute fingerprints inline using `LibKey.computeKeyFingerprint()` and store only fingerprints. KeyResolver serves as an optional lookup directory -- if you have a fingerprint and need the full public key, check KeyResolver or index `AttestationKeysRevealed` events from SessionRegistry.

The SessionRegistry emits full public keys in `AttestationKeysRevealed` events rather than storing them on-chain, making KeyResolver the canonical on-chain key→fingerprint directory for non-session keys (e.g., owner keys used to sign registration/deactivation operations).
