# SessionRegistry -- Detailed Analysis

**File**: `src/SessionRegistry.sol` (1,313 lines)
**Interface**: `src/interfaces/registries/ISessionRegistry.sol`
**Role**: Central orchestrator -- 9-step attestation verification pipeline, session lifecycle management

## Inheritance

```
ISessionRegistry
TpmVerifier (abstract, inherits TpmBase)
AkCollateralVerifier (abstract, inherits TpmBase)
OwnableUpgradeable
UUPSUpgradeable
```

Note: Both `TpmVerifier` and `AkCollateralVerifier` inherit `TpmBase` (diamond). Solidity C3 linearization resolves this -- single `tpmAttestation` immutable shared.

## Constants

```solidity
uint64 private constant DEFAULT_CVM_TTL = 30 days;       // Used when workload ttl == 0
uint256 private constant DCAP_RTMR3_OFFSET = 472;
uint256 private constant DCAP_RTMR3_SIZE = 48;
uint256 private constant DCAP_REPORT_DATA_OFFSET = 520;
uint256 private constant SNP_REPORT_ID_OFFSET = 0x140;
uint256 private constant SNP_REPORT_ID_SIZE = 32;
uint8 private constant GCP_BINDING_PCR_INDEX = 15;
uint256 private constant GCP_UUID_SIZE = 16;
```

## Immutables

| Variable | Type | Purpose |
|---|---|---|
| `teeVerifier` | `ITeeVerifier` | TEE attestation dispatcher |
| `signatureVerifier` | `ISignatureVerifier` | Cryptographic signature verification |
| `baseImageRegistry` | `IBaseImageRegistry` | Platform policy lookup |
| `workloadRegistry` | `IWorkloadRegistry` | Application policy lookup |
| `tpmAttestation` | `ITpmAttestation` | (inherited from TpmBase) TPM operations |

## Storage

| Variable | Type | Purpose |
|---|---|---|
| `_sessions` | `mapping(bytes32 => CVMSessionStorage)` | Session state |
| `_ownerNonces` | `mapping(bytes32 => uint256)` | Replay protection per owner |
| `_sessionFingerprintsToIds` | `mapping(bytes32 => bytes32)` | Session key fingerprint -> session ID |
| `__gap` | `uint256[47]` | Storage gap |

## Storage Struct

```solidity
// In ISessionRegistry.sol
struct CVMSessionStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    CVMSession session;
}

struct CVMSession {
    bytes32 akPubKeyFingerprint;
    bytes32 tpmSigningKeyFingerprint;
    bytes32 sessionKeyFingerprint;
    bytes32 baseImageId;
    bytes32 workloadId;
    bytes32 platformProfileId;
    bytes32 measurementVariantId;
    uint64 registeredAt;
    uint64 expiresAt;
}
```

## Internal Structs

```solidity
struct PolicyContext {
    PlatformProfile platformProfile;
    MeasurementVariant variant;
    WorkloadSpec workloadSpec;
}

struct SessionParams {
    bytes32 sessionId;
    bytes32 ownerFingerprint;
    bytes32 akPubKeyFingerprint;
    bytes32 tpmSigningKeyFingerprint;
    bytes32 sessionKeyFingerprint;
    bytes32 baseImageId;
    bytes32 workloadId;
    bytes32 platformProfileId;
    bytes32 measurementVariantId;
    uint64 expiresAt;
}

struct AttestationResult {
    PublicIdentity akPub;
    PublicIdentity certifiedKey;       // TPM signing key
    bytes32 akPubFingerprint;
    bytes32 tpmSigningKeyFingerprint;
    bytes32 ownerFingerprint;
    PcrValue[] pcrValues;
    bytes32 expectedPcr15;             // GCP binding (zero for Azure)
    bytes32 tpmSignatureHash;          // keccak256(tpmQuoteReport.tpmSignature)
}

struct RotationContext {
    bytes32 ownerFingerprint;
    bytes32 baseImageId;
    bytes32 workloadId;
    bytes32 platformProfileId;
    bytes32 measurementVariantId;
    uint64 expiresAt;                  // Preserved from old session
}
```

## The 9-Step Attestation Verification Pipeline

### Step 1: Policy Lookup (`_lookupPolicy`)
```
Input: workloadId, baseImageId, platformProfileId, variantId
Actions:
  - Check workload not revoked (revert WorkloadNotActive)
  - Check base image not revoked (revert BaseImageNotActive)
  - Check workload allows base image (revert BaseImageNotAllowed)
  - Fetch platform profile + variant via baseImageRegistry.getVariant()
    NOTE: getVariant() checks existence only; it does NOT prove platformProfileId belongs to baseImageId or variantId belongs to platformProfileId
  - Fetch workload spec via workloadRegistry.getWorkload()
Output: PolicyContext { platformProfile, variant, workloadSpec }
```

### Step 2: TEE Report Verification
```
Input: evidence.teeReport
Actions:
  - Call teeVerifier.verifyTeeReport(teeReport)
  - Revert TEEVerificationFailed if !result.valid
Output: TeeVerificationResult { valid, reportData (full quote body or report), teeType }
```

### Step 3: AK Collateral & TEE-AK Binding (`_verifyTeeAkBinding`)
```
Input: evidence.akPubCollateral, teeVerificationResult
Actions:
  - Call verifyAkCollateral(collateral) -> AkCollateralVerificationResult { valid, akPub, akPubFingerprint, bindingHash }
  - Revert AKCollateralVerificationFailed if !result.valid
  - Platform-specific binding:
    Azure (AzureAkPubJson):
      - Extract reportData via teeVerifier.extractDcapReportData(teeResult.reportData)
      - Verify reportData[0:32] == akResult.bindingHash AND reportData[32:64] == bytes32(0)
      - Return expectedPcr15 = bytes32(0)
    GCP (GcpCertChain) + TDX:
      - Extract UUID (16 bytes) from quoteBody at offset 520
      - Verify RTMR3 (at offset 472) == sha384(bytes48(0) || (bytes32(0) || UUID))
      - Compute expectedPcr15 = sha256(bytes32(0) || (bytes16(0) || UUID))
      - The 16-byte UUID is left-padded with zeros to fill each bank's register width (no intermediate hash).
    GCP (GcpCertChain) + SNP:
      - Extract report_id (32 bytes) from rawReport at offset 0x140
      - Compute expectedPcr15 = sha256(bytes32(0) || report_id)
Output: expectedPcr15
```

### Step 4: TPM Quote Verification (`_verifyTpmQuoteWithNonce`)
```
Input: evidence.tpmQuoteReport, akPub, ownerFingerprint
Actions:
  - Compute nonce = _ownerNonces[ownerFingerprint]
  - Compute expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce))
  - Call verifyTpmQuote(tpmQuoteReport, akPub, abi.encodePacked(expectedExtraData))
  - Revert TPMQuoteVerificationFailed if !result.valid
  - INCREMENT NONCE immediately (replay protection)
  - Extract tpmSignatureHash = keccak256(quoteReport.tpmSignature)
Output: pcrValues[], tpmSignatureHash
```

### Step 5: TPM Certify Verification (`_verifyCertifiedKey`)
```
Input: evidence.tpmCertifyReport, akPub
Actions:
  - Call verifyTpmCertify(tpmCertifyReport, akPub)
  - Revert TPMCertifyVerificationFailed if !result.valid
  - Extract certified key (TPM signing key) and fingerprint
Output: certifiedKey (PublicIdentity), certifiedKeyFingerprint
```

### Step 6: Session ID Computation & Key Delegation
```
Input: tpmSignatureHash, teeReportBytesHash, certifiedKey, sessionKeySignature, sessionKey
Actions:
  - teeReportBytesHash = teeVerifier.getTeeReportHash(evidence.teeReport)
  - sessionId = keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))
  - Revert SessionAlreadyExists if session exists
  - Delegation message = keccak256(abi.encode(DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint))
  - Verify: signatureVerifier.verify(certifiedKey, delegationMessage, sessionKeySignature)
  - Revert SessionKeyDelegationFailed if invalid
Output: sessionId, sessionKeyFingerprint
```

### Step 7: PCR Policy Evaluation (`_evaluatePolicy`)
```
Input: pcrValues from TPM quote, PolicyContext, expectedPcr15
Actions:
  - Merge platform invariants with variant overrides via _mergePcrSpecs()
    (overrides replace invariants at matching pcrIndex using bitmask approach)
  - Evaluate merged PCR specs against measured values (_evaluatePcrSpecs)
  - Evaluate workload PCR specs against measured values (_evaluatePcrSpecs)
    NOTE: SessionRegistry does not enforce a hard platform-vs-workload PCR index split; it evaluates whatever sorted specs the registries provide
  - For each PCR spec:
    STATIC: pcrValue.value == matchData[0]
    DYNAMIC_SUBSET: each pcrValue.eventLogHashes[i] must be in matchData set
    DYNAMIC_SUBSEQUENCE: matchData must appear as subsequence in eventLogHashes
  - If expectedPcr15 != 0: verify measured PCR15 value matches expectedPcr15
Output: All PCR checks pass (or revert PCRVerificationFailed / PCRNotFound)
```

### Step 8: Attribute Requirements Evaluation
```
Input: workloadSpec.requirements, merged platform+variant attributes
Actions:
  - Merge: _mergeAttributes(platformProfile.attributes, variant.attributes)
    (variant attrs override platform attrs at matching key)
  - For each requirement:
    - Find attribute with matching key (revert AttributeNotFound if missing)
    - If allowedValues non-empty: check value is in set (revert AttributeValueNotAllowed if not)
    - If allowedValues empty: just require key exists
Output: All requirements satisfied (or revert)
```

### Step 9: Owner Signature & Session Creation
```
Input: ownerIdentity, ownerSignature, expireAt, sessionId
Actions:
  - message = sha256(abi.encode(SESSION_REGISTER_MSG, block.chainid, address(this), expireAt, sessionId))
  - Verify owner signature over message (revert InvalidSignature)
  - Compute expiresAt:
    - If workloadSpec.ttl == 0: block.timestamp + DEFAULT_CVM_TTL (30 days)
    - Else: block.timestamp + workloadSpec.ttl
  - Store session with registeredAt = block.timestamp, expiresAt computed above
  - Map sessionKeyFingerprint -> sessionId in _sessionFingerprintsToIds
  - Emit SessionRegistered + AttestationKeysRevealed
Output: sessionId
```

## Public Functions

### `registerSession`
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
) external returns (bytes32 sessionId)
```

Executes the full 9-step pipeline.

### `revokeSession`
```solidity
function revokeSession(
    bytes32 sessionId,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true`
- Requires owner signature over `sha256(abi.encode(SESSION_REVOKE_MSG, chainid, address(this), expireAt, sessionId))`
- Emits: `SessionRevoked`

### `rotateSession`
```solidity
function rotateSession(
    bytes32 oldSessionId,
    bytes32 teeReportBytesHash,
    SessionRotationEvidence calldata rotationEvidence,
    uint64 expireAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId)
```

Rotation steps:
1. Load old session context, verify old TPM signing key fingerprint, AK fingerprint, owner fingerprint match
2. Run TPM quote verification with nonce (step 4)
3. Run TPM certify verification (step 5)
4. Verify rotation authorization: old TPM signing key signs `keccak256(abi.encode(ROTATION_DOMAIN, oldSessionId, newTpmSigningKeyFingerprint, newSessionKeyFingerprint, teeReportBytesHash))`
5. Compute new session ID from tpmSignatureHash + teeReportBytesHash
6. Verify session key delegation (step 6)
7. Look up policy and evaluate PCR + attributes (steps 7-8), with expectedPcr15=0 (no TEE re-attestation)
8. Owner signs `sha256(abi.encode(SESSION_ROTATE_MSG, chainid, address(this), expireAt, oldSessionId, newSessionId))`
9. Revoke old session, create new session **preserving old expiresAt** (NOT fresh TTL)
10. Emit SessionRotated + AttestationKeysRevealed

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getSession(sessionId)` | `CVMSession` | Reverts if not found |
| `getSessionId(sessionFingerprint)` | `bytes32` | Lookup by session key fingerprint |
| `getSessionOwner(sessionId)` | `bytes32` | Owner fingerprint |
| `isSessionActive(sessionId)` | `bool` | exists && !revoked && block.timestamp <= expiresAt |
| `isSessionExpired(sessionId)` | `bool` | `block.timestamp > expiresAt` (false if not exists) |
| `getNonce(ownerFingerprint)` | `uint256` | Current nonce for replay protection |

### `verifySessionSignature`
```solidity
function verifySessionSignature(
    bytes32 sessionId,
    PublicIdentity calldata sessionKey,
    bytes32 message,
    bytes calldata signature
) external view returns (bool valid)
```

- Checks session is active
- Verifies sessionKey fingerprint matches stored `sessionKeyFingerprint`
- Calls `signatureVerifier.verify(sessionKey, message, signature)` directly
- NOTE: Does NOT wrap message with SESSION_DOMAIN. Message is passed as-is to verifier.

## Errors

| Error | Condition |
|---|---|
| `InvalidSignature()` | Any signature check failed |
| `SignatureExpired()` | `block.timestamp > expireAt` |
| `SessionAlreadyExists()` | Duplicate session ID |
| `SessionNotFound()` | Session doesn't exist |
| `SessionNotActive()` | Session expired (used in rotation) |
| `SessionAlreadyRevoked()` | Already revoked |
| `Unauthorized()` | Fingerprint mismatch |
| `TEEVerificationFailed()` | TEE report invalid |
| `AKCollateralVerificationFailed()` | AK collateral invalid |
| `TEEAKBindingFailed()` | TEE-AK binding mismatch |
| `TPMQuoteVerificationFailed()` | TPM quote invalid |
| `TPMCertifyVerificationFailed()` | TPM certify invalid |
| `SessionKeyDelegationFailed()` | Delegation signature invalid |
| `PCRVerificationFailed()` | PCR policy mismatch |
| `PCRNotFound()` | Required PCR not in quote (no parameter) |
| `AttributeNotFound(bytes32 key)` | Required attribute missing |
| `AttributeValueNotAllowed(bytes32 key)` | Attribute value not in allowed set |
| `WorkloadNotActive(bytes32 workloadId)` | Referenced workload revoked |
| `BaseImageNotActive(bytes32 baseImageId)` | Referenced base image revoked |
| `BaseImageNotAllowed(bytes32 baseImageId)` | Workload doesn't allow this base image |

## Events

| Event | Fields |
|---|---|
| `SessionRegistered` | `sessionId (indexed), owner (indexed), workloadId (indexed), baseImageId, akPubKeyFingerprint, tpmSigningKeyFingerprint, sessionKeyFingerprint` |
| `AttestationKeysRevealed` | `sessionId (indexed), akPub, tpmSigningKey, sessionKey` (full public keys, never stored) |
| `SessionRevoked` | `sessionId (indexed), revoker (indexed)` |
| `SessionRotated` | `oldSessionId (indexed), newSessionId (indexed), owner (indexed), newTpmSigningKeyFingerprint, newSessionKeyFingerprint` |

## Key Implementation Details

### Nonce Binding & Increment Timing
The TPM quote `extraData` is bound to the owner's nonce. The nonce is incremented **immediately after** successful TPM quote verification (step 4), not at session creation (step 9). This means if steps 5-9 fail, the nonce is still consumed.
```
expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, ownerFingerprint, nonce))
// passed to verifyTpmQuote as: abi.encodePacked(expectedExtraData)
```

### PCR Merge Semantics
Uses bitmask-based merge: allocate 24-slot array, apply overrides first (building overrideMask), then insert invariants not covered by overrideMask, then compact.

### Attribute Merge Semantics
Platform attributes not overridden are kept, then all variant attributes are appended. Array is trimmed via assembly.

### Session ID Derivation
```
sessionId = keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))
```
Where:
- `tpmSignatureHash = keccak256(quoteReport.tpmSignature)` (from decoded TpmQuoteReport)
- `teeReportBytesHash = teeVerifier.getTeeReportHash(evidence.teeReport)` (keccak256 for Solidity, last 32 bytes for ZK)

### Key Storage Philosophy
Public keys (AK, TPM signing key, session key) are NEVER stored on-chain. Only their fingerprints are stored. Full keys are emitted in `AttestationKeysRevealed` event for off-chain indexing.

### Session Key Delegation Message
```
delegationMessage = keccak256(abi.encode(DELEGATION_DOMAIN, baseImageId, workloadId, sessionId, sessionKeyFingerprint))
```
This binds the session key to a specific base image, workload, and session.

### Rotation Key Differences from Registration
- TEE is NOT re-attested during rotation (teeReportBytesHash provided directly)
- GCP PCR15 binding check is skipped (expectedPcr15 = bytes32(0))
- Old session's `expiresAt` is preserved (NOT recomputed from TTL)
- Rotation authorization: old TPM signing key must sign rotation message
- Owner `expireAt` and owner signature are checked late in `_finalizeRotation`, after TPM quote verification has already consumed the owner's nonce

### Policy Lookup Caveat
`_lookupPolicy()` relies on `baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId)`, and that BaseImageRegistry helper only verifies that each ID exists. It does not enforce base-image/profile/variant lineage consistency.

### Internal Helpers
- `_requireNotExpired(expireAt)` -- reverts `SignatureExpired` if expired
- `_requireFingerprint(identity, expected)` -- reverts `Unauthorized` if mismatch
- `_requireSignature(signer, message, signature)` -- reverts `InvalidSignature` if invalid
- `_isSessionActive(storage)` -- exists && !revoked && block.timestamp <= expiresAt
- `_createSession(params)` -- stores session + updates fingerprint->ID mapping
- `_computeSessionId(tpmSignatureHash, teeReportBytesHash)` -- domain-separated keccak256
- `_mergePcrSpecs(invariants, overrides)` -- bitmask merge
- `_mergeAttributes(profileAttrs, variantAttrs)` -- override merge
- `_evaluatePcrSpecs(specs, pcrValues)` -- sorted merge-join evaluation
- `_evaluateSinglePcr(spec, measured)` -- STATIC/DYNAMIC_SUBSET/DYNAMIC_SUBSEQUENCE
- `_findPcrValue(pcrValues, pcrIndex)` -- linear scan
- `_evaluateAttributeRequirements(requirements, attributes)` -- key lookup + value check
