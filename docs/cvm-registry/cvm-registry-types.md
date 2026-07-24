# Types, Constants & Libraries -- Detailed Analysis

## Common.sol (`src/types/Common.sol`)

Core data structures shared across all registries.

### Enums

```solidity
enum PcrVerifyType {
    STATIC,               // Exact match: actual == expected
    DYNAMIC_SUBSET,       // matchData must occur in events (unordered)
    DYNAMIC_SUBSEQUENCE   // matchData must appear as subsequence in events (ordered)
}

enum AccessMode {
    ANY,        // All base images allowed
    BLACKLIST,  // Listed base images blocked
    WHITELIST   // Only listed base images allowed
}
```

### Primitive Structs

```solidity
struct PublicIdentity {
    uint8 typeId;    // Algorithm ID (0=NULL, 1=RS256, 2=ES256, 3=ES256K)
    bytes key;       // Raw public key bytes (format depends on typeId)
}

struct PcrSpec {
    uint8 pcrIndex;              // PCR register index (0-23)
    PcrVerifyType verifyType;    // How to evaluate this PCR
    bytes32[] matchData;         // Expected values (interpretation depends on verifyType)
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

### BaseImageRegistry Structs

```solidity
struct BaseImageSpec {
    string name;       // e.g. "automata-linux"
    string version;    // e.g. "v0.1.6"
    string uri;        // Reference URI
}

struct PlatformProfile {
    string name;               // e.g. "gcp-tdx", "azure-snp"
    PcrSpec[] invariants;      // PCR 0-19 baseline measurements
    Attribute[] attributes;    // Platform metadata (cloud, TEE type, etc.)
}

struct MeasurementVariant {
    string name;                // e.g. "n2d-standard-2", "c3-standard-4"
    PcrSpec[] overridePcrs;     // Replaces platform invariants at matching pcrIndex
    Attribute[] attributes;     // Replaces platform attributes at matching key
}
```

### WorkloadRegistry Structs

```solidity
struct WorkloadSpec {
    string name;
    string version;
    uint64 ttl;                              // Session TTL in seconds (0 = DEFAULT_CVM_TTL = 30 days)
    AccessMode baseImageMode;                // ANY / WHITELIST / BLACKLIST
    bytes32[] baseImageIds;                  // For whitelist/blacklist filtering
    AttributeRequirement[] requirements;     // Demanded platform attributes
    PcrSpec[] pcrs;                          // PCR 20-23 specs
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
    uint64 expiresAt;
}
```

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
struct ZkProof {
    bytes output;       // ZK circuit output
    bytes proofBytes;   // ZK proof
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
}
```

The stable bits represent Intel TDX debug (`1 << 0`), AMD SEV-SNP debug
(`1 << 1`), and AMD SEV-SNP `MIGRATE_MA` (`1 << 2`). Their canonical keys are
`keccak256` of these exact names:

- `atakit.attestation.v1.tee.intel-tdx.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.debug.enabled`
- `atakit.attestation.v1.tee.amd-sev-snp.migrate-ma.enabled`

Boolean values use only `bytes32(0)` and `bytes32(uint256(1))`.

### TPM Structs

```solidity
struct TpmReport {
    VerificationBackendType verificationBackendType;
    TpmReportType tpmReportType;
    bytes data;   // ABI-encoded TpmQuoteReport or TpmCertifyReport
}

struct TpmQuoteReport {
    bytes tpm2bAttest;       // Marshalled TPMS_ATTEST (no TPM2B size prefix). See note below.
    bytes tpmSignature;      // TPM signature over tpm2bAttest
    PcrValue[] pcrValues;    // PCR register values
}

struct TpmCertifyReport {
    bytes tpm2bAttest;       // Marshalled TPMS_ATTEST (no TPM2B size prefix). See note below.
    bytes tpmSignature;      // TPM signature over tpm2bAttest
    bytes tpmtPublic;        // TPMT_PUBLIC of certified key
}

// Note on `tpm2bAttest`: despite the field name, the bytes are the bare
// marshalled `TPMS_ATTEST` — i.e. they start with the TPM2.0 magic
// `0xFF544347` at offset 0. The 2-byte `TPM2B_ATTEST` size prefix the TPM
// ABI returns MUST be stripped before populating this field. TPM2.0
// signatures are computed over `TPMS_ATTEST` (not the size-prefixed
// `TPM2B_ATTEST`), and `LibTpm.parseAttestHeaders` reverts with
// `InvalidTpmMagic()` if the prefix is present.

// PcrValue imported from @automata-network/automata-tpm-attestation/types/Types.sol
struct PcrValue {
    uint8 pcrIndex;
    bytes32 value;              // Static PCR value
    bytes32[] eventLogHashes;   // Dynamic event log hashes (used by DYNAMIC_SUBSET/SUBSEQUENCE)
}
```

### AK Collateral

```solidity
struct AkPubCollateral {
    AkPubCollateralType akPubCollateralType;
    bytes data;   // Azure: abi.encode((bytes jwt, bytes hclVarData));
                  // GCP: ABI-encoded bytes[] certs
}
```

### Evidence Bundles

```solidity
struct AttestationEvidence {
    TeeReport teeReport;
    TpmReport tpmQuoteReport;
    TpmReport tpmCertifyReport;
    AkPubCollateral akPubCollateral;
    bytes sessionKeySignature;     // TPM signing key's signature delegating session key
    PublicIdentity sessionKey;     // The session key being delegated to
}

struct SessionRotationEvidence {
    TpmReport tpmQuoteReport;
    TpmReport tpmCertifyReport;
    bytes sessionKeySignature;
    PublicIdentity sessionKey;
    bytes rotationSignature;        // Old TPM signing key signs rotation message
    PublicIdentity oldTpmSigningKey;
    PublicIdentity akPub;
}
```

### TPM Verification Results (defined at file scope in TpmVerifier.sol)

```solidity
struct TpmQuoteVerificationResult {
    bool valid;
    PcrValue[] pcrValues;
}

struct TpmCertifyVerificationResult {
    bool valid;
    PublicIdentity certifiedKey;
    bytes32 certifiedKeyFingerprint;
}
```

### AK Collateral Verification Result (defined at file scope in AkCollateralVerifier.sol)

```solidity
struct AkCollateralVerificationResult {
    bool valid;
    PublicIdentity akPub;
    bytes32 akPubFingerprint;
    bytes32 bindingHash;   // Azure: sha256(hclVarData) (asserted equal to MAA JWT's
                           //   tdx_report_data / x-ms-sevsnpvm-reportdata claim prefix
                           //   inside verifyAkCollateral; not re-checked downstream)
                           // GCP: bytes32(0) (binding via PCR15 in SessionRegistry step 7)
}
```

---

## Constants.sol (`src/types/Constants.sol`)

### Domain Separators

All are `bytes32 constant = keccak256("...")`:

| Name | String | Purpose |
|---|---|---|
| `KEY_DOMAIN` | `"KEY_RESOLVER_V1"` | Key fingerprint computation |
| `SESSION_DOMAIN` | `"CVM_SESSION_V1"` | Session ID computation (`_computeSessionId` in `src/SessionRegistry.sol:687`) |
| `DELEGATION_DOMAIN` | `"CVM_SESSION_KEY_DELEGATION"` | TPM→session key delegation |
| `ROTATION_DOMAIN` | `"CVM_SESSION_KEY_ROTATION"` | Session key rotation |
| `BASEIMAGE_DOMAIN` | `"CVM_BASEIMAGE_V1"` | Base image ID computation |
| `PLATFORM_PROFILE_DOMAIN` | `"CVM_PLATFORM_PROFILE_V1"` | Platform profile ID |
| `PLATFORM_VARIANT_DOMAIN` | `"CVM_PLATFORM_VARIANT_V1"` | Variant ID |
| `WORKLOAD_DOMAIN` | `"CVM_WORKLOAD_V1"` | Workload ID |
| `SESSION_NONCE_DOMAIN` | `"CVM_SESSION_REG_NONCE_V1"` | Nonce-based replay protection |

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
| `SESSION_ROTATE_MSG` | `"CVM_MSG_SESSION_ROTATE_V1"` | rotateSession |

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
    bytes calldata proofBytes
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
