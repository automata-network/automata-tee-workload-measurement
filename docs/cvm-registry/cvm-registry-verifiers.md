# Verifier Contracts -- Detailed Analysis

## TeeVerifier

**File**: `src/TeeVerifier.sol` (298 lines)
**Interface**: `src/interfaces/ITeeVerifier.sol`
**Role**: Stateless dispatcher for TEE attestation verification (Intel TDX via DCAP, AMD SEV-SNP)

### Immutables

| Variable | Type | Purpose |
|---|---|---|
| `dcapAttestation` | `IDcapAttestation` | Intel DCAP verification backend |
| `snpAttestation` | `ISnpAttestation` | AMD SNP verification backend |

### Constants

```solidity
// Quote body type identifiers
uint16 constant QUOTE_BODY_TYPE_TD10 = 2;
uint16 constant QUOTE_BODY_TYPE_TD15 = 3;

// Quote body sizes
uint256 constant TD10_QUOTE_BODY_SIZE = 584;
uint256 constant TD15_QUOTE_BODY_SIZE = 648;

// Report data extraction
uint256 constant REPORT_DATA_SIZE = 64;
uint256 constant DCAP_REPORT_DATA_START = 520;  // offset within quote body

// SNP
uint256 constant SNP_REPORT_DATA_OFFSET = 0x50;
uint256 constant SNP_MIN_REPORT_LEN = 144;
```

### Version

```solidity
string public constant TEE_VERIFIER_VERSION = "1.0.0";
```

### Functions

#### `getTeeReportHash`
```solidity
function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32)
```
- Solidity backend: `keccak256(teeReport.data)`
- ZK backend: decodes `ZkProof` from data, extracts last 32 bytes of `zkProof.output`

#### `verifyTeeReport`
```solidity
function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory)
```

**TDX (Intel) flow**:
1. Dispatch based on `VerificationBackendType`:
   - Solidity: `dcapAttestation.verifyAndAttestOnChain(teeReport.data)`
   - ZK RiscZero/Succinct: `dcapAttestation.verifyAndAttestWithZKProof(output, zkCoprocessor, proofBytes)`
2. Extract quote body from DCAP output (`extractDcapQuoteBody`)
3. Extract 64-byte reportData from quote body (`extractDcapReportData`)

**SNP (AMD) flow**:
1. ZK only: `snpAttestation.verifyAndAttestWithZKProof(output, zkCoprocessor, proofBytes)`
2. Extract attestation report (`extractSnpAttestationReport`)
3. Extract 64-byte reportData (`extractSnpReportData`)

#### Helper Functions

| Function | Visibility | Purpose |
|---|---|---|
| `extractDcapQuoteBody(output)` | private | Parse DCAP output -> TD10/TD15 quote body bytes |
| `extractDcapReportData(quoteBody)` | external | Extract 64 bytes at offset 520 from quote body |
| `extractSnpAttestationReport(rawReport)` | private | Validate length >= 144, return raw report |
| `extractSnpReportData(rawReport)` | external | Extract 64 bytes at offset 0x50 from SNP report |

Additional constant: `DCAP_QUOTE_BODY_OFFSET = 11` (header: 2+2+1+6 bytes before quote body in DCAP output).

### Errors

| Error | Condition |
|---|---|
| `UnsupportedTeeType()` | Not TDX or SNP |
| `UnsupportedBackendType()` | Invalid verification backend |
| `InvalidTeeReport()` | Verification returned invalid |

---

## SignatureVerifier

**File**: `src/SignatureVerifier.sol` (172 lines)
**Interface**: `src/interfaces/ISignatureVerifier.sol`
**Role**: Stateless multi-algorithm signature verification

### Version & Immutables

```solidity
string public constant SIGNATURE_VERIFIER_VERSION = "1.0.0";
address public immutable P256_VERIFIER_ADDRESS;
```

### Dependencies

- OpenZeppelin `RSA` library (PKCS#1 v1.5 SHA-256)
- OpenZeppelin `ECDSA` library (secp256k1 recovery)
- External `P256Verifier` contract (for P-256/secp256r1) at `P256_VERIFIER_ADDRESS`
- Custom `Asn1Decode` library (DER parsing for RSA keys and P-256 signatures)

### Error

```solidity
error UnsupportedAlgorithm(uint8 typeId);
```

### Constructor

```solidity
constructor(address p256VerifierAddress)
```

### Function

```solidity
function verify(
    PublicIdentity calldata identity,
    bytes32 hash,
    bytes calldata signature
) external view returns (bool)
```

**Algorithm dispatch based on `identity.typeId`**:

#### RS256 (typeId = 1)
1. Parse DER-encoded PKCS#1 RSA public key from `identity.key`
2. Extract modulus (n) and exponent (e) via ASN.1 decoding
3. Call `RSA.pkcs1Sha256(hash, signature, e, n)`

#### ES256 (typeId = 2)
1. Validate `key.length == 65 && key[0] == 0x04` (SEC1 uncompressed point; `src/SignatureVerifier.sol:85`)
2. Extract x, y coordinates: `x = bytes32(key[1:33])`, `y = bytes32(key[33:65])`
3. Parse DER-encoded signature to extract r, s via ASN.1 decoding
4. Call external P256Verifier: `staticcall(p256Verifier, abi.encode(hash, r, s, x, y))`
5. Result: first 32 bytes of return value == 1

#### ES256K (typeId = 3)
1. Validate `key.length == 65 && key[0] == 0x04` (SEC1 uncompressed point; `src/SignatureVerifier.sol:119`)
2. Derive expected address from public key: `address(uint160(uint256(keccak256(key[1:65]))))`
3. Call `ECDSA.tryRecoverCalldata(hash, signature)` to recover signer address (calldata variant)
4. Compare recovered address with expected address and check no error

---

## TpmVerifier

**File**: `src/bases/TpmVerifier.sol` (197 lines)
**Inheritance**: `TpmBase` (abstract)
**Role**: TPM quote and certify verification

### Constants

```solidity
// Required TPMA_OBJECT attribute bits
uint32 constant TPMA_OBJECT_REQUIRED_SET = 0x40072;
// fixedTPM (0x2) | fixedParent (0x10) | sensitiveDataOrigin (0x20) | userWithAuth (0x40) | sign (0x40000)

// Forbidden TPMA_OBJECT bits (must be clear)
// Allowed bits (may be 0 or 1): {1,4,5,6,10,18} = 0x00040472
// stClear (bit 2) and adminWithPolicy (bit 7) are explicitly forbidden.
uint32 constant TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB8D;
```

### Functions

#### `verifyTpmQuote`
```solidity
function verifyTpmQuote(
    TpmReport memory tpmReport,
    PublicIdentity memory akPub,
    bytes memory expectedExtraData       // NOTE: bytes, not bytes32
) internal returns (TpmQuoteVerificationResult memory)
```

1. Validate `tpmReportType == TpmQuote`
2. Validate `verificationBackendType == Solidity` (ZK not yet supported)
3. Decode `TpmQuoteReport` from `tpmReport.data`
4. Convert `PublicIdentity` → `CertPubkey` for TPM library compatibility
5. Call `tpmAttestation.verifyTpmQuoteWithTrustedAkPub(tpm2bAttest, tpmSignature, akCertPubkey)`
6. Verify `keccak256(extractedExtraData) == keccak256(expectedExtraData)`
7. Call `tpmAttestation.checkPcrMeasurements(tpm2bAttest, pcrValues)`
8. Return: `{ valid: true, pcrValues }`

#### `verifyTpmCertify`
```solidity
function verifyTpmCertify(
    TpmReport memory tpmReport,
    PublicIdentity memory akPub
) internal view returns (TpmCertifyVerificationResult memory)
```

1. Validate `tpmReportType == TpmCertify`
2. Decode `TpmCertifyReport` from `tpmReport.data`
3. Validate CLEAR bits on `tpmtPublic[4:8]` (via `_validateClearBits`)
4. Call `tpmAttestation.verifyTpmKeyCertification(tpm2bAttest, tpmSignature, tpmtPublic, akCertPubkey, TPMA_OBJECT_REQUIRED_SET)`
5. Validate `TPMA_OBJECT` bits on `tpmtPublic`:
   - All `REQUIRED_SET` bits must be set
   - All `REQUIRED_CLEAR` bits must be clear
5. Convert certified key (`CertPubkey`) back to `PublicIdentity`
6. Return: `{ valid: true, certifiedKey, certifiedKeyFingerprint }`

### Errors

| Error | Condition |
|---|---|
| `UnexpectedTpmReportType()` | Wrong report type for operation |
| `UnsupportedTpmBackendType()` | ZK backends not yet implemented |
| `TpmQuoteExtraDataMismatch()` | Nonce binding check failed |
| `TpmQuotePcrCheckFailed()` | TPM PCR integrity check failed |
| `TpmQuoteLibraryFailed()` | TPM attestation library returned error |
| `TpmaObjectForbiddenBitsSet()` | Certified key has forbidden attributes |
| `TpmtPublicTooShort()` | tpmtPublic data too short to extract attributes |

---

## AkCollateralVerifier

**File**: `src/bases/AkCollateralVerifier.sol` (191 lines)
**Inheritance**: `TpmBase` (abstract)
**Role**: AK (Attestation Key) certificate chain / collateral validation

### Function

```solidity
function verifyAkCollateral(
    AkPubCollateral memory collateral
) internal returns (AkCollateralVerificationResult memory)
// Returns: { valid, akPub, akPubFingerprint, bindingHash }
```

Dispatches based on `collateral.akPubCollateralType`:

#### AzureMaaJwt
Azure delivers the AK public key inside an HCL `var_data` JWK document, anchored to the platform via a Microsoft Azure Attestation (MAA) signed JWT. Wire format is an ABI tuple:

```
abi.encode((bytes jwt, bytes hclVarData))
```

- `jwt` is a Microsoft Azure Attestation-signed JSON Web Token (RS256 / RSA-2048 / SHA-256) issued for `/attest/TdxVm` (TDX) or `/attest/SevSnpVm` (SNP).
- `hclVarData` is the JSON document from vTPM NV `0x01400001`, containing the `HCLAkPub` JWK.

Verification steps:
1. `abi.decode` `collateral.data` into `(bytes jwt, bytes hclVarData)`.
2. Split `jwt` on `.` into header / claims / signature parts (all base64url).
3. Base64url-decode the header; parse JSON; extract `kid` and `alg` (require `"RS256"`).
4. Look up MAA signing key by `keccak256(bytes(kid))` in the MAA Signing Key Registry; require `!revoked` and `block.timestamp <= notAfter`.
5. Verify the RS256 signature on `header || "." || claims` against the registered PKCS#1 RSA-2048 pubkey using `SignatureVerifier.verify`.
6. Base64url-decode the claims; parse JSON; assert:
   - `iss` matches `key.issuerHash`
   - `x-ms-attestation-type` in `{"tdxvm", "sevsnpvm"}`
   - `x-ms-compliance-status == "azure-compliant-cvm"`
7. Extract the report-data claim (`tdx_report_data` for TDX, `x-ms-sevsnpvm-reportdata` for SNP); hex-decode first 32 bytes as `bindingHash`; assert next 32 bytes decode to zero.
8. Assert `sha256(hclVarData) == bindingHash`.
9. Parse `HCLAkPub` from `hclVarData` using the §14.3-scoped JWK parser, construct `PublicIdentity` with `typeId = ALGO_ID_RS256`.

Binding: `sha256(hclVarData)` returned as `bindingHash` field. The on-chain `teeReport`'s `REPORT_DATA` is NOT separately verified against this hash — MAA's `tdx_report_data` / `x-ms-sevsnpvm-reportdata` claim is the on-chain binding to the TEE attestation.

#### GcpCertChain
GCP provides X.509 certificate chain:
1. ABI-decode `bytes[]` array of DER certificates from collateral data
2. Call `tpmAttestation.verifyCertChain(certs)` → returns `CertPubkey`
3. Convert `CertPubkey` → `PublicIdentity`

Binding: `bindingHash = bytes32(0)`. AK is bound to TEE via PCR15 computation (verified in SessionRegistry step 7).

### Errors

| Error | Condition |
|---|---|
| `UnsupportedAkCollateralType()` | Unknown collateral type |
| `AzureJwkParsingFailed()` | `HCLAkPub` JWK field extraction from `hclVarData` failed |
| `MaaJwtMalformed()` | JWT does not split into three base64url parts, or header/claims fail base64url/JSON decode |
| `MaaJwtAlgUnsupported()` | JWT header `alg` is not `"RS256"` |
| `MaaJwtHeaderClaimMissing()` | JWT header is missing `kid` or `alg` |
| `MaaJwtClaimMissing()` | JWT claims is missing a required field |
| `MaaKidNotRegistered()` | `kidHash` lookup in MAA Signing Key Registry returned an empty / revoked / expired key |
| `MaaJwtIssuerMismatch()` | `iss` claim hash does not equal `key.issuerHash` |
| `MaaJwtComplianceFailed()` | `x-ms-compliance-status` ≠ `"azure-compliant-cvm"`, or `x-ms-attestation-type` ∉ `{"tdxvm","sevsnpvm"}` |
| `MaaJwtReportDataMalformed()` | report_data claim has wrong length, non-hex chars, or non-zero padding |
| `MaaJwtSignatureInvalid()` | `signatureVerifier.verify` rejected the RS256 signature over `header || "." || claims` |
| `MaaJwtBindingMismatch()` | `sha256(hclVarData)` did not equal the report-data claim prefix |

---

## TpmBase

**File**: `src/bases/TpmBase.sol` (30 lines)
**Role**: Shared abstract base holding `ITpmAttestation` immutable

```solidity
abstract contract TpmBase {
    ITpmAttestation public immutable tpmAttestation;
    constructor(ITpmAttestation _tpmAttestation) {
        tpmAttestation = _tpmAttestation;
    }
}
```

Resolves diamond inheritance: both `TpmVerifier` and `AkCollateralVerifier` inherit `TpmBase`, and `SessionRegistry` inherits both. C3 linearization ensures single `tpmAttestation` instance.
