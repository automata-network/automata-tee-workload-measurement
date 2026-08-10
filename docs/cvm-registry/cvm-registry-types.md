# Types, Constants & Libraries -- Detailed Analysis

## Common.sol (`src/types/Common.sol`)

Core data structures shared across all registries.

### Enums

```solidity
enum AccessMode {
    ANY,        // All base images allowed
    BLACKLIST,  // Listed base images blocked
    WHITELIST   // Only listed base images allowed
}

enum PcrBankSelection {
    Sha256,
    Sha384,
    Sha256AndSha384
}
```

### Primitive Structs

```solidity
struct PublicIdentity {
    uint8 typeId;    // Algorithm ID (0=NULL, 1=RS256, 2=ES256, 3=ES256K)
    bytes key;       // Raw public key bytes (format depends on typeId)
}

struct PcrSpec256 {
    uint8 pcrIndex;
    bytes comparison;
}

struct PcrSpec384 {
    uint8 pcrIndex;
    bytes comparison;
}

struct PcrPolicyBlock {
    PcrSpec256[] pcrSpecs256;
    PcrSpec384[] pcrSpecs384;
}

struct PcrPolicyBlockMetadata {
    bytes32 blockHash;
    bytes3 pcrSelectBitmap256;
    bytes3 pcrSelectBitmap384;
}

struct PcrCommitment {
    bytes32 pcrSelect;
    bytes32 pcrDigest;
}

struct Attribute {
    bytes32 key;     // Attribute identifier
    bytes32 value;   // Attribute value
}

struct AttributeRequirement {
    bytes32 key;              // Required attribute key
    bytes32[] allowedValues;  // Accepted values (empty = any value, just require key exists)
}
```

`comparison` is one opaque canonical ABI blob. Its first field is a `uint16`
comparison type. `TpmVerifier` owns all type-specific decoding. Registries only
reject an empty `comparison`.

### BaseImageRegistry Structs

```solidity
struct BaseImageSpec {
    string name;       // e.g. "automata-linux"
    string version;    // e.g. "v0.1.6"
    string uri;        // Reference URI
}

struct PlatformProfile {
    string name;
    PcrBankSelection pcrBankSelection;
    PcrPolicyBlock invariantPcrPolicy;
    Attribute[] attributes;
}

struct MeasurementVariant {
    string name;
    PcrPolicyBlock variantPcrPolicy;
    Attribute[] attributes;
}
```

### WorkloadRegistry Structs

```solidity
struct WorkloadSpec {
    string name;
    string version;
    uint64 sessionTtl;                       // Session TTL in seconds (0 = DEFAULT_CVM_TTL = 30 days)
    AccessMode baseImageMode;                // ANY / WHITELIST / BLACKLIST
    bytes32[] baseImageIds;                  // For whitelist/blacklist filtering
    AttributeRequirement[] requirements;     // Demanded platform attributes
    PcrPolicyBlock workloadPcrPolicy;
}
```

### SessionRegistry Structs

```solidity
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

`registeredAt` is the creation timestamp of that session row. It is
informational. `rotateKey` creates a row with a new `registeredAt` but
preserves the predecessor's absolute `sessionExpiresAt`.

---

## Evidence.sol (`src/types/Evidence.sol`)

Attestation evidence data structures for the verification pipeline.

### Enums

```solidity
enum TEEType {
    IntelTDX,
    AmdSevSnp
}

enum VerificationBackendType {
    Solidity,       // Full on-chain verification
    ZkRiscZero,     // RiscZero ZK proof
    ZkSuccinct      // Succinct ZK proof
}

enum TpmReportType {
    TpmQuote,       // TPM quote with PCR values
    TpmCertify      // TPM key certification
}

enum AkPubCollateralType {
    AzureMaaJwt,     // Azure: abi.encode((bytes jwt, bytes hclVarData))
                     //   jwt: MAA-signed JWT (RS256) from /attest/TdxVm or /attest/SevSnpVm
                     //   hclVarData: vTPM NV 0x01400001 JSON; contains HCLAkPub
    GcpCertChain     // GCP X.509 certificate chain
}
```

### TEE Structs

```solidity
enum ZkProofType {
    IntelTdxDcap,
    AmdSevSnp,
    TpmQuote,
    AwsNitroTpm
}

struct ProgramBoundZkProof {
    bytes32 programIdentifier;
    bytes output;
    bytes proofBytes;
}

struct IntelTdxDcapZkEvidence {
    ProgramBoundZkProof proof;
    bytes quoteBody;
}

struct IntelTdxDcapJournalV1 {
    uint16 quoteVersion;
    uint16 quoteBodyType;
    uint8 tcbStatus;
    bytes6 fmspc;
    bytes32 fullQuoteHash;
    bytes32 quoteBodyHash;
}

struct AmdSevSnpZkEvidence {
    ProgramBoundZkProof proof;
    bytes rawReport;
}

struct TeeReport {
    VerificationBackendType verificationBackendType;
    TEEType teeType;
    bytes data;   // Raw TEE attestation report (or ZK proof)
}

struct TeeVerificationResult {
    bool valid;
    bytes reportData;    // Full report body (TDX: 584/648-byte quote body; SNP: full attestation report)
    TEEType teeType;     // Use extractDcapReportData/extractSnpReportData for 64-byte user data
    uint256 enabledTeeAttributes; // Stable internal bitset derived from the signed report
    uint256 intelTdxTcbStatusBit; // One-hot Intel DCAP TCB status; zero for AMD SEV-SNP
    bytes32 amdSevSnpTcbValues;
    uint64 amdSevSnpPlatformInfo;
    uint24 amdSevSnpCpuid;
    uint32 amdSevSnpReportVersion;
    uint64 amdSevSnpLaunchMitigationVector;
    uint64 amdSevSnpCurrentMitigationVector;
    bytes32 teeReportBytesHash;
}
```

Intel TDX uses `IntelTdxDcapZkEvidence`. The proof commits to both
`keccak256(fullRawQuote)` and `keccak256(quoteBody)`. The call supplies only
the exact TD10 or TD15 quote body. `TeeVerifier` checks the body hash and
returns the proof-bound exact signed quote hash as `teeReportBytesHash`.
Provider buffer padding is not part of the Intel TDX quote. AMD
SEV-SNP uses `AmdSevSnpZkEvidence` because the verifier needs the full report
body after checking
`keccak256(rawReport) == AmdSevSnpVerifierJournal.reportHash`.

The stable bits represent Intel TDX debug (`1 << 0`), AMD SEV-SNP debug
(`1 << 1`), and AMD SEV-SNP `MIGRATE_MA` (`1 << 2`). Their canonical keys are
`keccak256` of these exact names:

- `atakit.attestation.v1.tee.intel-tdx.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled`

Boolean values use only `bytes32(0)` and `bytes32(uint256(1))`.

The Intel TDX TCB policy key is
`keccak256("atakit.attestation.v1.tee.intel-tdx.tcb.status.allowed")`.
`intelTdxTcbStatusBit` uses `1 << rawDcapStatus`. Configurable raw statuses are
0 through 5, 8, and 9. The complete configurable mask is `0x33f`, and every
stored policy mask must include bit 0 (`ok`).

The AMD SEV-SNP packed policy keys are:

- `atakit.attestation.v1.tee.amd-sev-snp.tcb.minimum`
- `atakit.attestation.v1.tee.amd-sev-snp.platform-info.policy`

Their layouts are documented in
[AmdSnpSecurityPolicyRegistry](cvm-registry-amd-snp-policy.md).

### TPM Structs

```solidity
struct TpmReport {
    VerificationBackendType verificationBackendType;
    TpmReportType tpmReportType;
    bytes data;   // TpmQuoteEvidence, TpmCertifyEvidence, or ProgramBoundZkProof
}

struct TpmQuoteEvidence {
    bytes tpmsAttest;
    bytes tpmSignature;
    uint8 pcr0StartupLocality;
    PcrValue256[] pcrValues256;
    PcrValue384[] pcrValues384;
}

struct TpmCertifyEvidence {
    bytes tpmsAttest;
    bytes tpmSignature;
    bytes tpmtPublic;
}

struct PcrValue256 {
    uint8 pcrIndex;
    bytes32 value;
    bytes32[] eventLogHashes;
}

struct PcrValue384 {
    uint8 pcrIndex;
    Bytes48 value;
    Bytes48[] eventLogHashes;
}
```

### AK Collateral

```solidity
struct AkPubCollateral {
    AkPubCollateralType akPubCollateralType;
    VerificationBackendType verificationBackendType;
    bytes data;   // Azure: abi.encode((bytes jwt, bytes hclVarData));
                  // GCP: ABI-encoded bytes[] certs;
                  // AWS: abi.encode(ProgramBoundZkProof)
}
```

### Evidence Bundles

```solidity
struct AttestationEvidence {
    TeeReport teeReport;
    PublicIdentity akPub;
    TpmReport tpmQuoteReport;
    TpmReport tpmCertifyReport;
    AkPubCollateral akPubCollateral;
    bytes sessionKeySignature;     // abi.encode(TPM delegation signature, session-key possession signature)
    PublicIdentity sessionKey;     // The session key being delegated to
}

struct SessionKeyRotationEvidence {
    TpmReport tpmQuoteReport;
    TpmReport tpmCertifyReport;
    bytes sessionKeySignature;
    PublicIdentity sessionKey;
    bytes rotationSignature;        // Old TPM signing key signs rotation message
    PublicIdentity oldTpmSigningKey;
    PublicIdentity akPub;
}

struct SessionRenewalAuthorization {
    bytes signature;                     // Predecessor TPM key renewal commitment
    PublicIdentity oldTpmSigningKey;
}
```

### TPM Verification Results (defined at file scope in TpmVerifier.sol)

```solidity
struct TpmQuoteVerificationResult {
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    bytes32 tpmSignatureHash;
    PcrCommitment pcrCommitment;
    bytes32 policyCommitment;
}

struct TpmCertifyVerificationResult {
    bool valid;
    PublicIdentity certifiedKey;
    bytes32 certifiedKeyFingerprint;
}
```

### AK Collateral Verification Result (defined in `interfaces/IAkCollateralVerifier.sol`)

```solidity
struct AkCollateralVerificationResult {
    bytes32 akPubFingerprint;
    TEEType teeType;
    bytes32 bindingHash;
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    PcrCommitment pcrCommitment;
}
```

---

## Constants.sol (`src/types/Constants.sol`)

### Domain Separators

All are `bytes32 constant = keccak256("...")`:

| Name | String | Purpose |
|---|---|---|
| `KEY_DOMAIN` | `"KEY_RESOLVER_V1"` | Key fingerprint computation |
| `SESSION_DOMAIN` | `"CVM_SESSION_V1"` | Session ID computation |
| `DELEGATION_DOMAIN` | `"CVM_SESSION_KEY_DELEGATION"` | TPM→session key delegation |
| `SESSION_ROTATE_KEY_DOMAIN` | `"CVM_SESSION_ROTATE_KEY_V1"` | Old TPM key rotation commitment |
| `SESSION_RENEW_DOMAIN` | `"CVM_SESSION_RENEW_V1"` | Old TPM key renewal commitment |
| `BASEIMAGE_DOMAIN` | `"CVM_BASEIMAGE_V1"` | Base image ID computation |
| `PLATFORM_PROFILE_DOMAIN` | `"CVM_PLATFORM_PROFILE_V1"` | Platform profile ID |
| `PLATFORM_VARIANT_DOMAIN` | `"CVM_PLATFORM_VARIANT_V1"` | Variant ID |
| `WORKLOAD_DOMAIN` | `"CVM_WORKLOAD_V1"` | Workload ID |
| `SESSION_NONCE_DOMAIN` | `"CVM_SESSION_REG_NONCE_V1"` | Nonce-based replay protection |
| `PCR_POLICY_BLOCK_DOMAIN` | `"CVM_PCR_POLICY_BLOCK_V1"` | One named PCR policy block |
| `TPM_POLICY_COMMITMENT_DOMAIN` | `"CVM_TPM_POLICY_COMMITMENT_V1"` | Four named policy block hashes |
| `AWS_REPORT_DATA_PCR_COMMITMENT_DOMAIN` | `"CVM_AWS_REPORT_DATA_PCR_COMMITMENT_V1"` | AWS `REPORT_DATA[32:64]` binding |

### Operation Message Separators

All are `bytes32 constant = keccak256("...")`. Note the `CVM_MSG_` prefix and `_V1` suffix.

| Name | String | Used in |
|---|---|---|
| `BASEIMAGE_REGISTER_MSG` | `"CVM_MSG_BASEIMAGE_REGISTER_V1"` | registerBaseImage |
| `BASEIMAGE_DEACTIVATE_MSG` | `"CVM_MSG_BASEIMAGE_DEACTIVATE_V1"` | deactivateBaseImage |
| `BASEIMAGE_UPDATE_MSG` | `"CVM_MSG_BASEIMAGE_UPDATE_V1"` | addPlatformVariants |
| `WORKLOAD_REGISTER_MSG` | `"CVM_MSG_WORKLOAD_REGISTER_V1"` | registerWorkload |
| `WORKLOAD_DEACTIVATE_MSG` | `"CVM_MSG_WORKLOAD_DEACTIVATE_V1"` | deactivateWorkload |
| `SESSION_REGISTER_MSG` | `"CVM_MSG_SESSION_REGISTER_V1"` | registerSession |
| `SESSION_REVOKE_MSG` | `"CVM_MSG_SESSION_REVOKE_V1"` | revokeSession |
| `SESSION_ROTATE_KEY_MSG` | `"CVM_MSG_SESSION_ROTATE_KEY_V1"` | rotateKey |
| `SESSION_RENEW_MSG` | `"CVM_MSG_SESSION_RENEW_V1"` | renewSession |
| `SESSION_RECOVER_MSG` | `"CVM_MSG_SESSION_RECOVER_V1"` | recoverSession |

### Algorithm Identifiers

```solidity
uint8 constant ALGO_ID_NULL  = 0;   // No algorithm (empty identity)
uint8 constant ALGO_ID_RS256 = 1;   // RSA PKCS#1 v1.5 + SHA-256
uint8 constant ALGO_ID_ES256 = 2;   // ECDSA P-256 + SHA-256
uint8 constant ALGO_ID_ES256K = 3;  // ECDSA secp256k1 + SHA-256
```

---

## Libraries

### LibKey.sol (`src/lib/LibKey.sol`)

Key identity conversions and fingerprinting.

```solidity
function computeKeyFingerprint(PublicIdentity memory identity) → bytes32
// Returns: keccak256(abi.encode(KEY_DOMAIN, identity.typeId, identity.key))
//   (abi.encode pads each field to 32 bytes; this is NOT abi.encodePacked / concat.)

function certPubkeyToPublicIdentity(CertPubkey memory certPubkey) → PublicIdentity
// Maps TPM algorithm constants to our algo IDs:
//   TPM_ALG_RSA → ALGO_ID_RS256
//   TPM_ALG_ECC → ALGO_ID_ES256

function publicIdentityToCertPubkey(PublicIdentity memory identity) → CertPubkey
// Reverse mapping: ALGO_ID_RS256 → TPM_ALG_RSA, etc.
```

### AmdSnpPolicy.sol (`src/lib/AmdSnpPolicy.sol`)

The single definition of the packed AMD SEV-SNP policy formats and of the
supported-silicon window. `TeeVerifier` and `AmdSnpSecurityPolicyRegistry` both
depend on it so the two never drift.

```solidity
function validateTcb(bytes32 packedTcb)
function isValidTcb(bytes32 packedTcb) → bool
function tcbMeetsMinimum(bytes32 actual, bytes32 minimum) → bool

function validatePlatformInfoPolicy(bytes32 packedPolicy)
function isValidPlatformInfoPolicy(bytes32 packedPolicy) → bool
function tryMergePlatformInfoPolicies(bytes32 left, bytes32 right) → (bool ok, bytes32 merged)
function platformInfoMatches(uint64 actual, bytes32 packedPolicy) → bool

function isSupportedCpuid(uint24 cpuid) → bool
```

`validateTcb` reverts `InvalidAmdSnpTcbValue(bytes32 actual)` and
`validatePlatformInfoPolicy` reverts
`InvalidAmdSnpPlatformInfoPolicy(bytes32 actual)`.

`tryMergePlatformInfoPolicies` does not revert. It returns `ok = false` when
one side requires a bit set that the other requires cleared, leaving the caller
to report the conflict in its own terms — `AmdSnpSecurityPolicyRegistry` raises
`TeeAttributePolicyConflict(key, baseValue, workloadValue)`, which names the
attribute and both contributing values. `merged` is only meaningful when `ok`
is true.

`isSupportedCpuid` accepts AMD family `0x19`, models `0x00` through `0x1f`
(Milan and Genoa), and does not constrain the stepping byte; policy is keyed on
the exact CPUID including stepping. `TeeVerifier` applies it when extracting a
report and the registry applies it when admitting a policy, so widening the
window means redeploying `TeeVerifier` as well — see the runbook in
[Verifiers](cvm-registry-verifiers.md).

### LibBytes.sol (`src/lib/LibBytes.sol`)

Structured byte types and utilities.

```solidity
struct Bytes64 { bytes32 first; bytes32 second; }   // 64-byte value
struct Bytes48 { bytes32 first; bytes16 second; }   // 48-byte value

function readBytes48(bytes memory input, uint256 offset) → Bytes48
function readBytes64(bytes memory input, uint256 offset) → Bytes64
function readBytes32(bytes memory input, uint256 offset) → bytes32
function readBytes4(bytes memory input, uint256 offset) → bytes4
function readBytes2(bytes memory input, uint256 offset) → bytes2
function equal(Bytes48 a, Bytes48 b) → bool
function equal(bytes memory a, bytes memory b) → bool
function slice(bytes memory subject, uint256 start, uint256 len) → bytes
function toString(Bytes48) → string   // hex representation
```

`toBytes48` and `toBytes64` require exactly 48 and 64 input bytes and revert
`InvalidLength()` otherwise.

### Sha2Ext.sol (`src/lib/Sha2Ext.sol`)

Pure Solidity SHA-384/512 implementation (EVM only has SHA-256 natively).

```solidity
function sha384(bytes memory message) → Bytes48
function sha512(bytes memory message) → (bytes32, bytes32)

// Internal helpers:
function padMessage(bytes memory message) → bytes   // SHA-2 1024-bit block padding
function ch(a, b, c), maj(a, b, c)                  // SHA-2 logical functions
function sigma0(x), sigma1(x), gamma0(x), gamma1(x) // SHA-2 rotation functions
function rotateRight(x, n) → uint64
```

Used for GCP TDX RTMR3 binding verification (SHA-384).
An invalid internal padding length reverts `Sha2PaddingError()`.

### Asn1Decode.sol (`src/lib/Asn1Decode.sol`)

ASN.1 DER structure parsing using pointer-based traversal.

```solidity
// Pointer packing: uint256 contains three uint80 values
// NodePtr.ixs(ptr) = start index
// NodePtr.ixf(ptr) = first content byte index
// NodePtr.ixl(ptr) = last content byte index

function root(bytes memory der) → uint256           // Root node pointer
function firstChildOf(bytes memory der, uint256 ptr) → uint256
function nextSiblingOf(bytes memory der, uint256 ptr) → uint256
function bytesAt(bytes memory der, uint256 ptr) → bytes
function bytes32At(bytes memory der, uint256 ptr) → bytes32
function uintAt(bytes memory der, uint256 ptr) → uint256
function uintBytesAt(bytes memory der, uint256 ptr) → bytes  // Variable-length uint
```

Used by `SignatureVerifier` to parse RSA public keys and P-256 signatures.

### BytesUtils.sol (`src/lib/BytesUtils.sol`)

General byte string utilities.

```solidity
function keccak(bytes memory subject, uint256 offset, uint256 len) → bytes32
function compare(bytes memory self, bytes memory other) → int256  // lexicographic
function substring(bytes memory self, uint256 offset, uint256 len) → bytes
function readBytesN(bytes memory data, uint256 offset, uint256 len) → bytes32
function readBytes8(bytes memory data, uint256 offset) → uint64
```

---

## External Interfaces

### IDcapAttestation.sol
Intel DCAP (Data Center Attestation Primitives):
```solidity
enum ZkCoProcessorType { None, RiscZero, Succinct }

function verifyAndAttestOnChain(bytes calldata input) → (bool, bytes memory)
function verifyAndAttestWithZKProof(
    bytes calldata output,
    ZkCoProcessorType zkCoprocessor,
    bytes calldata proofBytes,
    bytes32 programIdentifier,
    uint32 tcbEvaluationDataNumber
) → (bool, bytes memory)
```

### ISnpAttestation.sol
AMD SEV-SNP:
```solidity
struct VerifierJournal {
    VerificationResult result;
    uint64 timestamp;
    uint8 processorModel;
    bytes rawReport;
    bytes32[] certs;
    uint160[] certSerials;
    uint8 trustedCertsPrefixLen;
}

function verifyAndAttestWithZKProof(
    bytes calldata output,
    ZkCoProcessorType zkCoprocessor,
    bytes calldata proofBytes
) → VerifierJournal memory
```

### INitroEnclaveVerifier.sol
AWS Nitro Enclaves (interface exists but not yet integrated into TeeVerifier).

---

## Mock Contracts

| Mock | Purpose |
|---|---|
| `MockTpmAttestation` | Stub TPM operations for testing |
| `MockSignatureVerifier` | Always-true signature verification |
| `MockAutomataDcapAttestation` | Stub DCAP verification |
| `MockAutomataSnpAttestation` | Stub SNP verification |
