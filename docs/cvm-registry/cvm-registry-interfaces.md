# CVM Registry Interfaces -- Complete Reference

**Path**: `src/interfaces/` with sub-directories `registries/` and `external/`

## Directory Layout

```
src/interfaces/
├── ISignatureVerifier.sol
├── ITeeVerifier.sol
├── registries/
│   ├── IBaseImageRegistry.sol
│   ├── IWorkloadRegistry.sol
│   ├── ISessionRegistry.sol
│   ├── IKeyResolver.sol
│   └── IMaaKeyRegistry.sol
└── external/
    ├── IDcapAttestation.sol
    ├── ISnpAttestation.sol
    └── INitroEnclaveVerifier.sol
```

Note: Registry interfaces are under `interfaces/registries/`, NOT directly under `interfaces/`.

---

## IBaseImageRegistry

**File**: `src/interfaces/registries/IBaseImageRegistry.sol`

### Storage Structs (defined at file scope, outside interface)

```solidity
struct BaseImageSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    BaseImageSpec spec;
    bytes32[] platformProfileIds;
}

struct PlatformProfileStorage {
    bool exists;
    PlatformProfile platformProfile;
    bytes32[] variantIds;
}

struct MeasurementVariantStorage {
    bool exists;
    MeasurementVariant measurementVariant;
}
```

### Events

```solidity
event BaseImageRegistered(bytes32 indexed baseImageId, bytes32 indexed owner, string name, string version);
event BaseImageDeactivated(bytes32 indexed baseImageId, bytes32 indexed owner);
event PlatformProfileRegistered(bytes32 indexed baseImageId, bytes32 indexed platformProfileId, string name);
event MeasurementVariantRegistered(bytes32 indexed platformProfileId, bytes32 indexed variantId, string name);
event BaseImageUpdated(bytes32 indexed baseImageId, bytes32 indexed owner);
```

### Function Signatures

```solidity
function registerBaseImage(
    BaseImageSpec calldata spec,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,                                      // NOTE: uint64, not uint256
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 baseImageId);

function deactivateBaseImage(
    bytes32 baseImageId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function addPlatformVariants(
    bytes32 baseImageId,
    PlatformProfile[] calldata platformProfiles,
    MeasurementVariant[][] calldata measurementVariants,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function getBaseImage(bytes32 baseImageId) external view returns (BaseImageSpec memory spec);
function getPlatformProfile(bytes32 platformProfileId) external view returns (PlatformProfile memory);
function getMeasurementVariant(bytes32 variantId) external view returns (MeasurementVariant memory);
function getVariant(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
    external view returns (BaseImageSpec memory, PlatformProfile memory, MeasurementVariant memory);
function getBaseImageOwner(bytes32 baseImageId) external view returns (bytes32);
function isBaseImageRevoked(bytes32 baseImageId) external view returns (bool);
function hasVariant(bytes32 variantId) external view returns (bool);
```

---

## IWorkloadRegistry

**File**: `src/interfaces/registries/IWorkloadRegistry.sol`

### Storage Struct (file scope)

```solidity
struct WorkloadSpecStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    WorkloadSpec workloadSpec;
}
```

### Events

```solidity
event WorkloadRegistered(bytes32 indexed workloadId, bytes32 indexed owner, string name, string version);
event WorkloadDeactivated(bytes32 indexed workloadId, bytes32 indexed owner);
```

### Function Signatures

```solidity
function registerWorkload(
    WorkloadSpec calldata spec,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 workloadId);

function deactivateWorkload(
    bytes32 workloadId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function getWorkload(bytes32 workloadId) external view returns (WorkloadSpec memory spec);
function getWorkloadOwner(bytes32 workloadId) external view returns (bytes32);
function isWorkloadRevoked(bytes32 workloadId) external view returns (bool);
function isBaseImageAllowed(bytes32 workloadId, bytes32 baseImageId) external view returns (bool);
```

---

## ISessionRegistry

**File**: `src/interfaces/registries/ISessionRegistry.sol`

### Storage Struct (file scope)

```solidity
struct CVMSessionStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    CVMSession session;
}
```

### Events

```solidity
event SessionRegistered(
    bytes32 indexed sessionId,
    bytes32 indexed owner,
    bytes32 indexed workloadId,
    bytes32 baseImageId,
    bytes32 akPubKeyFingerprint,
    bytes32 tpmSigningKeyFingerprint,
    bytes32 sessionKeyFingerprint
);

event AttestationKeysRevealed(
    bytes32 indexed sessionId,
    PublicIdentity akPub,
    PublicIdentity tpmSigningKey,
    PublicIdentity sessionKey
);

event SessionRevoked(bytes32 indexed sessionId, bytes32 indexed revoker);

event SessionRotated(
    bytes32 indexed oldSessionId,
    bytes32 indexed newSessionId,
    bytes32 indexed owner,
    bytes32 newTpmSigningKeyFingerprint,
    bytes32 newSessionKeyFingerprint
);
```

### Function Signatures

```solidity
function registerSession(
    AttestationEvidence calldata evidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 variantId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 sessionId);

function getSession(bytes32 sessionId) external view returns (CVMSession memory session);
function getSessionId(bytes32 sessionFingerprint) external view returns (bytes32 sessionId);
function getSessionOwner(bytes32 sessionId) external view returns (bytes32 ownerFingerprint);

function revokeSession(
    bytes32 sessionId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function isSessionActive(bytes32 sessionId) external view returns (bool);
function isSessionExpired(bytes32 sessionId) external view returns (bool);
function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce);

function rotateSession(
    bytes32 oldSessionId,
    bytes32 teeReportBytesHash,
    SessionRotationEvidence calldata rotationEvidence,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId);

function verifySessionSignature(
    bytes32 sessionId,
    PublicIdentity calldata sessionKey,
    bytes32 message,                      // NOTE: bytes32, not bytes calldata
    bytes calldata signature
) external view returns (bool valid);
```

---

## IKeyResolver

**File**: `src/interfaces/registries/IKeyResolver.sol`

### Events

```solidity
event IdentityRegistered(bytes32 indexed fingerprint, uint8 typeId);
```

### Function Signatures

```solidity
function registerIdentity(PublicIdentity calldata identity) external returns (bytes32 fingerprint);
function getIdentity(bytes32 fingerprint) external view returns (PublicIdentity memory identity);
function hasIdentity(bytes32 fingerprint) external view returns (bool);
function computeFingerprint(PublicIdentity calldata identity) external pure returns (bytes32 fingerprint);
```

---

## IMaaKeyRegistry

**File**: `src/interfaces/registries/IMaaKeyRegistry.sol`

Admin-managed directory of Microsoft Azure Attestation signing keys consumed by `AkCollateralVerifier` when verifying `AzureMaaJwt` collateral. Distinct from `IKeyResolver` because the stored value shape (PKCS#1 RSA pubkey + issuer + validity + revocation) and lifecycle (rotation, expiry, admin revocation) differ from a `PublicIdentity` directory.

### Types

```solidity
struct MaaSigningKey {
    bytes pkcs1Pubkey;     // DER PKCS#1 RSAPublicKey, ~270 bytes for RSA-2048
    bytes32 issuerHash;    // keccak256(bytes("https://<region>.attest.azure.net"))
    uint64 notAfter;       // Unix seconds; from leaf cert NotAfter
    bool revoked;
}
```

### Events

```solidity
event MaaSigningKeyUpserted(bytes32 indexed kidHash, bytes32 issuerHash, uint64 notAfter);
event MaaSigningKeyRevoked(bytes32 indexed kidHash);
```

### Function Signatures

```solidity
function upsertMaaSigningKey(
    bytes32 kidHash,
    bytes calldata pkcs1Pubkey,
    bytes32 issuerHash,
    uint64 notAfter,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function revokeMaaSigningKey(
    bytes32 kidHash,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external;

function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory);
function hasMaaSigningKey(bytes32 kidHash) external view returns (bool);
```

Owner-signed admin operations use `MAA_KEY_UPSERT_MSG` / `MAA_KEY_REVOKE_MSG` separators with chainid + address(this) for replay protection (same pattern as the other registries).

---

## ISignatureVerifier

**File**: `src/interfaces/ISignatureVerifier.sol`

```solidity
interface ISignatureVerifier {
    function verify(
        PublicIdentity calldata identity,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool valid);
}
```

NatDoc: "Foundation of the owner-auth model - allows TEE-managed keys (RSA, ECDSA-P256, etc.) to own registry entries directly without relying on msg.sender addresses"

---

## ITeeVerifier

**File**: `src/interfaces/ITeeVerifier.sol`

```solidity
interface ITeeVerifier {
    function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32);
    function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory result);
    function extractDcapReportData(bytes memory quoteBody) external pure returns (bytes memory reportData);
    function extractSnpReportData(bytes memory rawReport) external pure returns (bytes memory reportData);
}
```

---

## IDcapAttestation (External)

**File**: `src/interfaces/external/IDcapAttestation.sol`

```solidity
enum ZkCoProcessorType { None, RiscZero, Succinct }

interface IDcapAttestation {
    function getBp() external view returns (uint16);

    function verifyAndAttestOnChain(bytes calldata input)
        external payable returns (bool success, bytes memory output);

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external payable returns (bool success, bytes memory verifiedOutput);
}
```

Note: `verifyAndAttestOnChain` and `verifyAndAttestWithZKProof` are both `payable` (fee-based verification). `getBp()` returns the base price in basis points.

---

## ISnpAttestation (External)

**File**: `src/interfaces/external/ISnpAttestation.sol`

### Types (file scope)

```solidity
enum VerificationResult { Success, RootCertNotTrusted, IntermediateCertsNotTrusted, InvalidTimestamp }

struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}
```

### Interface

```solidity
interface ISnpAttestation {
    enum ZkCoProcessorType { None, RiscZero, Succinct }

    function verifyAndAttestWithZKProof(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory verifiedOutput);
}
```

Note: SNP only supports ZK proof verification (no on-chain equivalent of `verifyAndAttestOnChain`).

---

## INitroEnclaveVerifier (External)

**File**: `src/interfaces/external/INitroEnclaveVerifier.sol`

### Types (file scope)

```solidity
struct VerifierInput {
    uint8 trustedCertsPrefixLen;
    bytes attestationReport;            // COSE_Sign1 format
}

struct VerifierJournal {
    VerificationResult result;
    uint8 trustedCertsPrefixLen;
    uint64 timestamp;                   // Unix milliseconds
    bytes32[] certs;
    bytes userData;
    bytes nonce;
    bytes publicKey;
    Pcr[] pcrs;
    string moduleId;
}

struct BatchVerifierJournal {
    bytes32 verifierVk;
    VerifierJournal[] outputs;
}

struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

struct Pcr {
    uint64 index;
    Bytes48 value;                       // SHA-384 measurement
}

enum VerificationResult { Success, RootCertNotTrusted, IntermediateCertsNotTrusted, InvalidTimestamp }
```

### Interface

```solidity
interface INitroEnclaveVerifier {
    enum ZkCoProcessorType { Unknown, RiscZero, Succinct }

    function verify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal memory);

    function batchVerify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    ) external returns (VerifierJournal[] memory);
}
```

Note: Nitro Enclave verifier is **not yet integrated** into `TeeVerifier` -- the interface exists but `TeeVerifier` only dispatches to DCAP (TDX) and SNP. Also supports batch verification via `batchVerify`. Uses `Unknown` instead of `None` for the no-ZK case (unlike DCAP/SNP).

---

## Key Observations Across Interfaces

1. **All `expireAt` parameters are `uint64`** -- not `uint256`. Consistent across all registry interfaces.

2. **Storage structs are defined at file scope** (outside the interface block) -- this is required because Solidity interfaces cannot contain struct definitions with storage semantics.

3. **`verifySessionSignature` takes `bytes32 message`** -- the message is passed directly to `signatureVerifier.verify()` without any domain wrapping. Caller is responsible for pre-hashing.

4. **DCAP is `payable`** -- verification calls to Intel DCAP can charge fees (basis points via `getBp()`).

5. **SNP is ZK-only** -- no on-chain verification method, only `verifyAndAttestWithZKProof`.

6. **Nitro not yet integrated** -- interface exists with both single and batch verification, but `TeeVerifier` doesn't route to it yet.

7. **IKeyResolver has `IdentityRegistered` event** -- emits `(fingerprint, typeId)` on new registrations.

8. **Whitelist events/functions are NOT in interfaces** -- `addToWhitelist`, `removeFromWhitelist`, `isWhitelisted`, `WhitelistAdded`, `WhitelistRemoved` are implementation-only (in BaseImageRegistry and WorkloadRegistry contracts, not their interfaces). Same for `pause()`/`unpause()`.
