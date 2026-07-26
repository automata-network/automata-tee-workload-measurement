# SessionRegistry -- Detailed Analysis

**File**: `src/SessionRegistry.sol`
**Interface**: `src/interfaces/registries/ISessionRegistry.sol`
**Role**: Central orchestrator for attestation verification and session lifecycle management

## Inheritance

```
ISessionRegistry
TpmVerifier (abstract, inherits TpmBase)
OwnableUpgradeable
UUPSUpgradeable
```

AK collateral verification is delegated through an immutable
`IAkCollateralVerifier` constructor dependency. It is external to keep the
registry runtime below the EIP-170 bytecode limit.

## Constants

```solidity
uint64 private constant DEFAULT_CVM_TTL = 30 days;       // Used when workload sessionTtl == 0
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
| `akCollateralVerifier` | `IAkCollateralVerifier` | External Azure/GCP AK collateral verification |
| `baseImageRegistry` | `IBaseImageRegistry` | Platform policy lookup |
| `workloadRegistry` | `IWorkloadRegistry` | Application policy lookup |
| `amdSnpSecurityPolicyRegistry` | `IAmdSnpSecurityPolicyRegistry` | Global AMD SEV-SNP policy and verified TEE attribute evaluation |
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
    uint64 sessionExpiresAt;
}
```

`registeredAt` records when that session row was created. Full registration,
renewal, recovery, and rotation all set it to the current block timestamp.
`rotateKey` still preserves the predecessor's absolute `sessionExpiresAt`.
No activity check uses `registeredAt`.

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
    uint64 sessionExpiresAt;
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
    uint64 sessionExpiresAt;                  // Preserved from old session
}

struct FullSessionResult {
    AttestationResult attestation;
    bytes32 sessionId;
    bytes32 sessionKeyFingerprint;
    uint64 sessionExpiresAt;
}
```

## Session Registration Verification Sequence

### Step 1: Policy Lookup (`_lookupPolicy`)
```
Input: workloadId, baseImageId, platformProfileId, variantId
Actions:
  - Check workload not revoked (revert WorkloadNotActive)
  - Check base image not revoked (revert BaseImageNotActive)
  - Check workload allows base image (revert BaseImageNotAllowed)
  - Fetch platform profile + variant via baseImageRegistry.getVariant()
    NOTE: getVariant() enforces parent-child binding -- platformProfileId MUST have been registered under baseImageId AND variantId MUST have been registered under platformProfileId, or it reverts HierarchyMismatch. SessionRegistry relies on this to prevent cross-base-image PCR policy substitution.
  - Fetch workload spec via workloadRegistry.getWorkload()
Output: PolicyContext { platformProfile, variant, workloadSpec }
```

### Step 2: TEE Report Verification
```
Input: evidence.teeReport
Actions:
  - Call teeVerifier.verifyTeeReport(teeReport)
  - Revert TeeVerificationFailed if !result.valid
Output: TeeVerificationResult { valid, reportData (full quote body or report), teeType, enabledTeeAttributes, intelTdxTcbStatusBit, amdSevSnpTcbValues, amdSevSnpPlatformInfo, amdSevSnpCpuid }
```

### Step 2a: Verified TEE and Attribute Policy

This step runs immediately after TEE verification. It uses `teeType` to
evaluate only the reserved attributes for the verified TEE platform.
`enabledTeeAttributes` carries the three reserved Boolean states.

`SessionRegistry` calls
`AmdSnpSecurityPolicyRegistry.verifyTeePolicy` with the verified state,
profile attributes, variant attributes, and workload requirements. Despite its
AMD-specific name, this function evaluates Intel TDX policy and ordinary
metadata too. It performs all attribute checks here, before AK and TPM
verification, to keep `SessionRegistry` below the EIP-170 code-size limit.
It evaluates ordinary metadata requirements first, then the applicable
reserved policy.

For each reserved key, the policy registry merges profile and variant
attributes, with the variant value replacing the profile value. A missing
base-image value means `false`. Every declared base-image value must equal the
verified report value.

The matching Boolean workload requirement defaults to `[false]` when missing.
A stored Boolean requirement is valid only when its allowed values are
`[false]` or `[false, true]`. The verified value must appear in that list.

For Intel TDX, `intelTdxTcbStatusBit` is `1 << rawDcapStatus`. The effective
base-image mask and workload mask each default to `0x1`, which permits only
`ok`. Both masks must contain the verified bit. A measurement-variant mask
replaces the matching profile mask.

For AMD SEV-SNP, SessionRegistry passes the verified CPUID, four packed TCB
values, and `PLATFORM_INFO` to `AmdSnpSecurityPolicyRegistry`. The registry
requires an active policy for that exact CPUID. It applies the global policy
as a floor, then applies the base-image and workload packed policies. Packed
AMD SEV-SNP values use the same measurement-variant-first lookup. The selected
`tcb.minimum` value is combined component by component with the global and
workload minimums. The selected `platform-info.policy` value is merged with
the global and workload required-set and required-clear masks. Conflicting
masks fail.

The contract recognizes only the six exact reserved attribute hashes listed
in [Types, Constants & Libraries](cvm-registry-types.md). It cannot
recover a textual namespace from an arbitrary `bytes32` key. Therefore,
unknown hashes keep ordinary metadata semantics on chain. Authoring tools must
reject an unknown textual name under `atakit.attestation.v1.tee.` before
hashing it.

The selected `teeType` comes from `TeeVerifier` after a type-specific
verification path succeeds. The caller supplies `TeeReport.teeType`, but a
false label cannot make the other report format pass the selected parser and
cryptographic verifier. The selected type does not come from a profile name or
base-image publisher field. SessionRegistry evaluates only the reserved
attributes assigned to `teeResult.teeType`. A base image may contain
declarations for both Intel TDX and AMD SEV-SNP. Declarations for the other
TEE platform are not evaluated for the current session.

### Step 3: AK Collateral & TEE-AK Binding (`_verifyTeeAkBinding`)
```
Input: evidence.akPubCollateral, teeVerificationResult
Actions:
  - Call the external akCollateralVerifier.verifyAkCollateral(collateral)
    -> AkCollateralVerificationResult { valid, akPub, akPubFingerprint, bindingHash }
  - AkCollateralVerifier reverts on every failure and returns valid=true on success.
    SessionRegistry does not branch on this result's valid field.
  - Platform-specific binding:
    Azure (AzureMaaJwt):
      - verifyAkCollateral (§8.3.1):
        - abi.decode (bytes jwt, bytes hclVarData) from collateral.data
        - Verify the MAA-signed RS256 JWT against the per-region signing key
          looked up by JWT header `kid` in the MAA Signing Key Registry (§10.3)
        - Assert iss, x-ms-attestation-type in {"tdxvm","sevsnpvm"}, and
          x-ms-compliance-status == "azure-compliant-cvm"
        - Hex-decode the first 32 bytes of tdx_report_data (TDX) or
          x-ms-sevsnpvm-reportdata (SNP); next 32 bytes must be zero
        - Assert sha256(hclVarData) equals those 32 bytes
        - Parse HCLAkPub from hclVarData using the §14.3-scoped JWK parser
      - akResult.bindingHash = sha256(hclVarData)
      - For TDX, extract the 64-byte REPORT_DATA at quote-body offset 520
      - For SNP, extract the 64-byte REPORT_DATA at report offset 0x50
      - Require REPORT_DATA = akResult.bindingHash || bytes32(0)
      - Return expectedPcr15 = bytes32(0)
    GCP (GcpCertChain) + TDX:
      - Extract UUID (16 bytes) from quoteBody at offset 520
      - Verify RTMR3 (at offset 472) == sha384(bytes48(0) || (bytes32(0) || UUID))
      - Compute expectedPcr15 = sha256(bytes32(0) || (bytes16(0) || UUID))
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
  - Compute expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(this), ownerFingerprint, nonce))
  - Call verifyTpmQuote(tpmQuoteReport, akPub, abi.encodePacked(expectedExtraData))
  - The verifier reverts with a specific TpmVerifier error on failure
  - Write the nonce increment immediately; it persists only if the transaction succeeds
  - Extract tpmSignatureHash = keccak256(quoteReport.tpmSignature)
Output: pcrValues[], tpmSignatureHash
```

### Step 5: TPM Certify Verification (`_verifyCertifiedKey`)
```
Input: evidence.tpmCertifyReport, akPub
Actions:
  - Call verifyTpmCertify(tpmCertifyReport, akPub)
  - The verifier reverts with a specific TpmVerifier error on failure
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
  - Delegation message = keccak256(abi.encode(DELEGATION_DOMAIN, block.chainid, address(this), baseImageId, workloadId, sessionId, sessionKeyFingerprint))
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
    DYNAMIC_SUBSET: pcrValue.eventLogHashes must be non-empty AND every matchData entry must occur in the event log (order irrelevant; extra observed events permitted)
      (empty event log is rejected — the TPM lib skips the value↔events hash-chain check when
      events are empty, so accepting empty would let an attacker submit any `value` and bypass
      the policy)
    DYNAMIC_SUBSEQUENCE: pcrValue.eventLogHashes must be non-empty AND matchData must appear
      as a subsequence (same empty-event-log rejection rationale)
  - If expectedPcr15 != 0: verify measured PCR15 value matches expectedPcr15
Output: All PCR checks pass, or the contract reverts with
`PCRStaticMismatch`, `PCREventLogEmpty`, `PCRSubsetLandmarkMissing`,
`PCRSubsequenceLandmarkMissing`, `PCRNotFound`, or `GcpPcr15Mismatch`
```

### Attribute Requirements Evaluation (executed in Step 2a)

The implementation executes these rules inside
`AmdSnpSecurityPolicyRegistry.verifyTeePolicy` during Step 2a. There is no
second attribute-evaluation call after the PCR checks.
```
Input: workloadSpec.requirements, merged platform+variant attributes
Actions:
  - For each key, search variant attributes first and profile attributes second
    (a variant value therefore overrides the matching profile value)
  - Skip all six reserved verified TEE attribute keys because Step 2a already handled the applicable platform keys
  - For each ordinary requirement:
    - Find attribute with matching key (revert AttributeNotFound if missing)
    - If allowedValues non-empty: check value is in set (revert AttributeValueNotAllowed if not)
    - If allowedValues empty: just require key exists
Output: All requirements satisfied (or revert)
```

### Step 8: Owner Signature & Session Creation
```
Input: ownerIdentity, ownerSignature, opExpiresAt, sessionId
Actions:
  - message = sha256(abi.encode(SESSION_REGISTER_MSG, block.chainid, address(this), opExpiresAt, sessionId, workloadId, baseImageId, platformProfileId, variantId, sessionKeyFingerprint))
  - Verify owner signature over message (revert InvalidSignature)
  - Compute sessionExpiresAt:
    - If workloadSpec.sessionTtl == 0: block.timestamp + DEFAULT_CVM_TTL (30 days)
    - Else: block.timestamp + workloadSpec.sessionTtl
  - Store session with registeredAt = block.timestamp, sessionExpiresAt computed above
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
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 sessionId)
```

Executes the complete registration sequence documented above.

### `revokeSession`
```solidity
function revokeSession(
    bytes32 sessionId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external
```

- Sets `isRevoked = true`
- Requires owner signature over `sha256(abi.encode(SESSION_REVOKE_MSG, chainid, address(this), opExpiresAt, sessionId))`
- Emits: `SessionRevoked`

### `rotateKey`
```solidity
function rotateKey(
    bytes32 oldSessionId,
    bytes32 teeReportBytesHash,
    SessionKeyRotationEvidence calldata rotationEvidence,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId)
```

Rotation steps:
1. Load old session context, verify old TPM signing key fingerprint, AK fingerprint, owner fingerprint match
2. Run TPM quote verification with nonce (step 4)
3. Run TPM certify verification (step 5)
4. Verify rotation authorization: old TPM signing key signs `keccak256(abi.encode(SESSION_ROTATE_KEY_DOMAIN, block.chainid, address(this), oldSessionId, newTpmSigningKeyFingerprint, newSessionKeyFingerprint, teeReportBytesHash))`
5. Compute new session ID from tpmSignatureHash + teeReportBytesHash
6. Verify session key delegation (step 6)
7. Require the inherited workload and base image to remain active, require
   the base image to remain allowed by the workload, and evaluate the current
   PCR rules with expectedPcr15=0. Rotation has no new TEE report, so it does
   not re-evaluate verified TEE attributes or the current AMD global policy;
   it inherits the security state accepted by the predecessor's full
   attestation.
8. Owner signs `sha256(abi.encode(SESSION_ROTATE_KEY_MSG, chainid, address(this), opExpiresAt, oldSessionId, newSessionId))`
9. Revoke old session, create new session **preserving old sessionExpiresAt** (NOT fresh TTL)
10. Emit SessionRevoked + SessionKeyRotated + AttestationKeysRevealed

### `renewSession`

```solidity
function renewSession(
    bytes32 oldSessionId,
    AttestationEvidence calldata newEvidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 measurementVariantId,
    SessionRenewalAuthorization calldata renewalAuthorization,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId)
```

Renew requires an active predecessor and its TPM signing key. It runs the full
attestation, delegation, and policy pipeline for the successor, verifies the
old TPM key's `CVM_SESSION_RENEW_V1` commitment to the complete ABI-encoded new
evidence, and verifies the owner's complete successor tuple under
`CVM_MSG_SESSION_RENEW_V1`. It may change the AK and policy tuple, grants a
fresh `sessionTtl`, atomically revokes the predecessor, and emits
`SessionRevoked`, `SessionRegistered`, `AttestationKeysRevealed`, and
`SessionRenewed`.

### `recoverSession`

```solidity
function recoverSession(
    bytes32 oldSessionId,
    AttestationEvidence calldata newEvidence,
    bytes32 workloadId,
    bytes32 baseImageId,
    bytes32 platformProfileId,
    bytes32 measurementVariantId,
    uint64 opExpiresAt,
    PublicIdentity calldata ownerIdentity,
    bytes calldata ownerSignature
) external returns (bytes32 newSessionId)
```

Recover requires an existing owner-controlled predecessor, which may already
be revoked or expired. It needs no predecessor TPM key, performs complete
successor verification, and grants a fresh lifetime. It emits
`SessionRevoked` only when newly revoking the predecessor, followed by
`SessionRegistered`, `AttestationKeysRevealed`, and `SessionRecovered`.

## Cloud Instance and Session Lifetime

`SessionRegistry` verifies a cryptographic TEE, vTPM, and key chain. It does
not store a GCP or Azure provider instance identifier and it cannot start,
stop, delete, or recreate a cloud virtual machine.

Session expiry is enforced when contracts read the session. After
`block.timestamp > sessionExpiresAt`, `isSessionActive` returns `false` and
`verifySessionSignature` rejects the session. Expiry needs no maintenance
transaction, but it does not terminate the cloud virtual machine.

If the cloud virtual machine stops while the on-chain session is still within
its lifetime, the session record remains on chain. `SessionRegistry` does not
recover the virtual machine. Cloud orchestration must restart or replace it.
A replacement that needs a trusted session must submit fresh attestation:

- `rotateKey` changes the TPM signing key and session key. It uses the same AK,
  policy tuple, and absolute `sessionExpiresAt`; it does not extend the
  session or verify a new TEE report.
- `renewSession` requires an active predecessor and authorization from its TPM
  signing key. It verifies complete new attestation and assigns a fresh
  policy-derived expiry.
- `recoverSession` requires the predecessor record and owner authorization but
  not the predecessor TPM signing key. It verifies complete new attestation,
  may replace an inactive predecessor, and assigns a fresh policy-derived
  expiry.

These functions change on-chain session state. They do not change cloud
provider resources.

### View Functions

| Function | Returns | Notes |
|---|---|---|
| `getSession(sessionId)` | `CVMSession` | Reverts if not found |
| `getSessionId(sessionFingerprint)` | `bytes32` | Lookup by session key fingerprint |
| `getSessionOwner(sessionId)` | `bytes32` | Owner fingerprint |
| `isSessionActive(sessionId)` | `bool` | exists && !revoked && block.timestamp <= sessionExpiresAt && !workloadRegistry.isWorkloadRevoked(workloadId) && !baseImageRegistry.isBaseImageRevoked(baseImageId). **Cascades**: revoking the underlying workload or base image flips every dependent session inactive on the next read. |
| `isSessionExpired(sessionId)` | `bool` | `block.timestamp > sessionExpiresAt` (false if not exists) |
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

- Checks session is active (cascades through workload/base-image revocation — see `isSessionActive` above)
- Verifies sessionKey fingerprint matches stored `sessionKeyFingerprint`
- Calls `signatureVerifier.verify(sessionKey, message, signature)` directly
- NOTE: Does NOT wrap message with SESSION_DOMAIN. Message is passed as-is to verifier.

## Errors

| Error | Condition |
|---|---|
| `InvalidSignature(bytes32 messageHash, bytes32 signerFingerprint)` | Any owner or TPM-signed message check failed |
| `SignatureExpired(uint64 opExpiresAt, uint64 nowTs)` | `block.timestamp > opExpiresAt` |
| `SessionAlreadyExists()` | Duplicate session ID |
| `SessionNotFound()` | Session doesn't exist |
| `SessionNotActive()` | A rotation or renewal predecessor is revoked, expired, or inactive because its workload or base image is revoked |
| `SessionAlreadyRevoked()` | Already revoked |
| `Unauthorized(bytes32 actualFingerprint, bytes32 expectedFingerprint)` | Fingerprint mismatch |
| `UnsupportedAzureTeeType(TEEType teeType)` | Azure collateral paired with an unsupported TEE |
| `UnsupportedGcpTeeType(TEEType teeType)` | GCP collateral paired with an unsupported TEE |
| `UnsupportedAkCollateralForBinding(AkPubCollateralType collateralType)` | No TEE-to-AK binding rule for the collateral type |
| `AzureTeeReportDataTooShort(uint256 actualLength, uint256 minRequired)` | Verified Azure TEE result cannot contain the 64-byte `REPORT_DATA` |
| `AzureTeeReportDataMismatch(bytes32 actualBindingHash, bytes32 expectedBindingHash, bytes32 actualPadding)` | Verified Azure TEE report does not contain the MAA-signed HCL binding followed by 32 zero bytes |
| `GcpTdxRtmr3Mismatch(bytes actualRtmr3, bytes expectedRtmr3)` | GCP TDX RTMR3 binding mismatch |
| `SessionKeyDelegationFailed(bytes32 messageHash, bytes32 sessionKeyFingerprint)` | Delegation signature invalid |
| `PCRStaticMismatch(uint8 pcrIndex, bytes32 measured, bytes32 expected)` | Static PCR mismatch |
| `PCREventLogEmpty(uint8 pcrIndex, PcrVerifyType verifyType)` | Dynamic PCR supplied no events |
| `PCRSubsetLandmarkMissing(uint8 pcrIndex, uint256 matchIdx, bytes32 matchHash)` | Required dynamic-subset landmark absent from the observed event log |
| `PCRSubsequenceLandmarkMissing(uint8 pcrIndex, uint256 matchedCount, uint256 expectedCount)` | Dynamic-subsequence landmark missing |
| `GcpPcr15Mismatch(bytes32 measured, bytes32 expected)` | PCR15 does not match the GCP TEE binding |
| `PCRNotFound(uint8 pcrIndex)` | Required PCR not in quote |
| `AttributeNotFound(bytes32 key)` | Required attribute missing |
| `AttributeValueNotAllowed(bytes32 key, bytes32 actualValue)` | Ordinary attribute value not in allowed set |
| `TeeVerificationFailed()` | A verifier implementation returned `valid=false` |
| `TeeAttributeBaseImageMismatch(bytes32 key, bytes32 declaredValue, bytes32 verifiedValue)` | Effective base-image declaration differs from the signed report |
| `TeeAttributeValueNotAllowed(bytes32 key, bytes32 actualValue)` | Reserved workload policy does not permit the verified state |
| `TeeAttributePolicyConflict(bytes32 key, bytes32 baseValue, bytes32 workloadValue)` | Combined AMD SEV-SNP `PLATFORM_INFO` policies require the same bit to be both set and clear |
| `WorkloadNotActive(bytes32 workloadId)` | Referenced workload revoked |
| `BaseImageNotActive(bytes32 baseImageId)` | Referenced base image revoked |
| `BaseImageNotAllowed(bytes32 baseImageId)` | Workload doesn't allow this base image |

## Events

| Event | Fields |
|---|---|
| `SessionRegistered` | `sessionId (indexed), owner (indexed), workloadId (indexed), baseImageId, akPubKeyFingerprint, tpmSigningKeyFingerprint, sessionKeyFingerprint` |
| `AttestationKeysRevealed` | `sessionId (indexed), akPub, tpmSigningKey, sessionKey` (full public keys, never stored) |
| `SessionRevoked` | `sessionId (indexed), revoker (indexed)` |
| `SessionKeyRotated` | `oldSessionId (indexed), newSessionId (indexed), owner (indexed), newTpmSigningKeyFingerprint, newSessionKeyFingerprint` |
| `SessionRenewed` | `oldSessionId (indexed), newSessionId (indexed), owner (indexed)` |
| `SessionRecovered` | `oldSessionId (indexed), newSessionId (indexed), owner (indexed)` |

> **Cascade revocations emit no `SessionRegistry` event.** When the underlying workload or base image is revoked, every dependent session transitions active→inactive on the next read (see `isSessionActive` above), but **no `SessionRevoked` is emitted** for those sessions. The only on-chain signal is `BaseImageDeactivated` from `BaseImageRegistry` or `WorkloadDeactivated` from `WorkloadRegistry`. Indexers/dashboards that track session lifecycle must subscribe to all three registries and treat each upstream deactivation as a cascading deactivation of every session whose `baseImageId` / `workloadId` matches.

## Key Implementation Details

### Nonce Binding & Increment Timing
The TPM quote `extraData` is bound to the owner's nonce. The contract writes
the increment immediately after successful TPM quote verification in Step 4.
The increment persists only when the complete transaction succeeds. Any later
revert rolls it back with every other state change in the transaction.
```
expectedExtraData = keccak256(abi.encode(SESSION_NONCE_DOMAIN, block.chainid, address(this), ownerFingerprint, nonce))
// passed to verifyTpmQuote as: abi.encodePacked(expectedExtraData)
```

### PCR Merge Semantics
Uses bitmask-based merge: allocate 24-slot array, apply overrides first (building overrideMask), then insert invariants not covered by overrideMask, then compact.

### Attribute Merge Semantics
Platform attributes not overridden are kept, then all variant attributes are appended. Array is trimmed via assembly.

Reserved Boolean TEE attributes use the same merge and default to `false`. The
Intel TDX TCB mask uses the same merge and defaults to `ok`. AMD SEV-SNP packed
values use the same merge and default to zero. Key rotation does not contain a
new TEE report and cannot change the workload, base image, profile, or variant.
It therefore inherits the verified launch policy and does not run the reserved
TEE attribute check again.

This version assumes a clean cutover in which every session was created under
this implementation. Compatibility with session storage written by an earlier
implementation is outside this version.

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
delegationMessage = keccak256(abi.encode(DELEGATION_DOMAIN, block.chainid, address(this), baseImageId, workloadId, sessionId, sessionKeyFingerprint))
```
This binds the session key to a specific base image, workload, and session.

### Rotation Key Differences from Registration
- TEE is NOT re-attested during rotation (teeReportBytesHash provided directly)
- GCP PCR15 binding check is skipped (expectedPcr15 = bytes32(0))
- Old session's `sessionExpiresAt` is preserved (NOT recomputed from TTL)
- Rotation authorization: old TPM signing key must sign rotation message
- Owner `opExpiresAt` and owner signature are checked late in
  `_finalizeRotation`, after TPM quote verification writes the nonce
  increment. A failure rolls that write back with the transaction.

### Policy Lookup Invariant
`_lookupPolicy()` relies on `baseImageRegistry.getVariant(baseImageId, platformProfileId, variantId)` to enforce parent-child binding (platform profile registered under the supplied base image; variant registered under the supplied platform profile). On mismatch `getVariant` reverts `HierarchyMismatch(baseImageId, platformProfileId, variantId)`, which propagates out of `_lookupPolicy` and causes registration / rotation to fail. This prevents a caller from pairing their target `baseImageId` with an unrelated platform profile / variant and verifying PCRs against a weaker policy.

### Internal Helpers
- `_requireNotExpired(opExpiresAt)` -- reverts `SignatureExpired` if expired
- `_requireFingerprint(identity, expected)` -- reverts `Unauthorized` if mismatch
- `_requireSignature(signer, message, signature)` -- reverts `InvalidSignature` if invalid
- `_isSessionActive(storage)` -- exists && !revoked && block.timestamp <= sessionExpiresAt && !workloadRegistry.isWorkloadRevoked(session.workloadId) && !baseImageRegistry.isBaseImageRevoked(session.baseImageId) (fail-closed cascade)
- `_createSession(params)` -- stores session + updates fingerprint->ID mapping
- `_computeSessionId(tpmSignatureHash, teeReportBytesHash)` -- domain-separated keccak256
- `_mergePcrSpecs(invariants, overrides)` -- bitmask merge
- `_evaluatePcrSpecs(specs, pcrValues)` -- sorted merge-join evaluation
- `_evaluateSinglePcr(spec, measured)` -- STATIC/DYNAMIC_SUBSET/DYNAMIC_SUBSEQUENCE
- `_findPcrValue(pcrValues, pcrIndex)` -- linear scan
