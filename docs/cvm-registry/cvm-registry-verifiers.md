# Verifier Contracts -- Detailed Analysis

## TeeVerifier

**File**: `src/TeeVerifier.sol`
**Interface**: `src/interfaces/ITeeVerifier.sol`
**Role**: Stateless dispatcher for TEE attestation verification (Intel TDX via DCAP, AMD SEV-SNP)

### Immutables

| Variable | Type | Purpose |
|---|---|---|
| `dcapAttestation` | `IDcapAttestation` | Intel DCAP verification backend |
| `snpAttestation` | `ISnpAttestation` | AMD SNP verification backend |
| `intelTdxDcapProgramIdentifier` | `bytes32` | Exact accepted Succinct SP1 TDX DCAP program |
| `amdSevSnpProgramIdentifier` | `bytes32` | Exact accepted Succinct SP1 SEV-SNP program |

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
uint256 constant SNP_REPORT_SIZE = 1184;
```

### Version

```solidity
string public constant TEE_VERIFIER_VERSION = "1.4.1";
```

### Functions

#### `getTeeReportHash`
```solidity
function getTeeReportHash(TeeReport memory teeReport) external pure returns (bytes32)
```
- Solidity backend: `keccak256(teeReport.data)`
- Intel TDX ZK backend: reads `keccak256(raw TDX quote)` from the end of the
  length-prefixed output, immediately before the exact 200-byte collateral section
- AMD SEV-SNP ZK backend: reads the trailing `reportHash` from the SNP journal

#### `verifyTeeReport`
```solidity
function verifyTeeReport(TeeReport memory teeReport) external returns (TeeVerificationResult memory)
```

**TDX (Intel) flow**:
1. Dispatch based on `VerificationBackendType`:
   - Solidity: `dcapAttestation.verifyAndAttestOnChain(teeReport.data)`
   - ZK Succinct only: `dcapAttestation.verifyAndAttestWithZKProof(output, Succinct, proofBytes, intelTdxDcapProgramIdentifier, 0)`
2. Accept raw DCAP TCB statuses 0 through 5, 8, and 9. Reject 6, 7, and unknown values.
3. Return the accepted status as `intelTdxTcbStatusBit = 1 << rawStatus`.
4. Extract the quote body from DCAP output.
5. Require valid reserved attribute bits and `SEPT_VE_DISABLE`.
6. Reject nonzero Intel TDX 1.5 `MR_SERVICETD`.
7. Extract `DEBUG` into `enabledTeeAttributes`.
8. Return the quote body with `valid=true`.

**SNP (AMD) flow**:
1. ZK Succinct only: `snpAttestation.verifyAndAttestWithZKProof(output, Succinct, amdSevSnpProgramIdentifier, proofBytes)`
2. Check the proof-bound report hash before reading report fields
3. Require an exact 1,184-byte report and version 3 through 5
4. Validate signature selection, key settings, policy, `VMPL`, raw TCB,
   CPUID, `PLATFORM_INFO`, and every version-specific reserved field
5. Accept only an all-zero or all-`0xff` `REPORT_ID_MA` as no active
   migration-agent association. Reject every other value.
6. Require `reported_tcb <= committed_tcb <= current_tcb` and
   `launch_tcb <= committed_tcb`, component by component. `LAUNCH_TCB` is the
   `COMMITTED_TCB` captured at launch and `COMMITTED_TCB` only ever advances,
   so it can never exceed the current value.
7. Extract `POLICY.DEBUG`, `POLICY.MIGRATE_MA`, four normalized TCB fields,
   `PLATFORM_INFO`, exact CPUID, and report version
8. For version 5, extract `LAUNCH_MIT_VECTOR` and `CURRENT_MIT_VECTOR`.
   Earlier versions return zero for both vectors.
9. Return the raw report with `valid=true`.

`AmdSnpSecurityPolicyRegistry` checks the extracted AMD state against the
resolved base-image and workload policies. Its active exact-CPUID record
supplies any missing packed value. See
[AmdSnpSecurityPolicyRegistry](cvm-registry-amd-snp-policy.md).

#### Runbook: vendor firmware introduces a new bit or version

`TeeVerifier` rejects every field value it does not recognize. That is
deliberate — an unknown bit is unreviewed silicon or firmware behaviour, and
admitting it would attest to a configuration nobody has evaluated. The cost is
that a vendor change can halt attestation for a platform until the verifier is
redeployed. Know this before it happens in production rather than during an
incident.

The gates that a vendor change can trip:

| Gate | Location | Rejects |
|---|---|---|
| `SNP_PLATFORM_INFO_SUPPORTED_MASK` (`0x3f`) | `TeeVerifier`, `AmdSnpPolicy` | `PLATFORM_INFO` bit 6 or above |
| SNP report version `3..5` | `TeeVerifier` | A version-6 report |
| SNP `POLICY` bit 26 and above | `TeeVerifier` | A newly defined policy bit |
| `AmdSnpPolicy.isSupportedCpuid` | `TeeVerifier`, `AmdSnpSecurityPolicyRegistry` | Family other than `0x19`, or model above `0x1f` (Turin) |
| TD_ATTRIBUTES reserved masks | `TeeVerifier` | A newly defined Intel TDX attribute bit |
| DCAP TCB statuses `6`, `7`, and above `9` | `TeeVerifier` | An unrecognized DCAP status |

**`TeeVerifier` is not upgradeable.** It holds its vendor verifier addresses as
immutables and sits behind no proxy, and `SessionRegistry.teeVerifier` is
likewise immutable. Widening any gate above is therefore a two-contract
operation, not a policy edit:

1. Deploy a new `TeeVerifier` with the widened constants and the exact accepted
   TDX and SEV-SNP program identifiers.
2. Deploy a new `SessionRegistry` implementation constructed against that
   address and `upgradeToAndCall` the `SessionRegistry` proxy.
3. Only then relax the corresponding policy, if any.

`script/UpgradeTeeVerifier.s.sol` performs both steps and asserts the rewiring
afterwards. Note the ordering constraint already encoded there: upgrade
`AmdSnpSecurityPolicyRegistry` **first**, because `SessionRegistry` calls
`verifyTeePolicy` with the current `VerifiedTeePolicyInputs` layout.

`AmdSnpSecurityPolicyRegistry` is a UUPS proxy and *is* upgradeable, so
`isSupportedCpuid` is shared between the two contracts to keep the supported
window defined once. Widening it in the registry alone still has no effect —
`TeeVerifier` rejects the report before the registry is ever consulted.

#### Helper Functions

| Function | Visibility | Purpose |
|---|---|---|
| `extractDcapQuoteBody(output)` | private | Parse DCAP output -> TD10/TD15 quote body bytes |
| `extractDcapReportData(quoteBody)` | external | Extract 64 bytes at offset 520 from quote body |
| `extractSnpAttestationReport(rawReport)` | private | Require the exact 1,184-byte report and validate policy fields |
| `extractSnpReportData(rawReport)` | external | Extract 64 bytes at offset 0x50 from SNP report |

Additional constant: `DCAP_QUOTE_BODY_OFFSET = 11` (header: 2+2+1+6 bytes before quote body in DCAP output).

### Errors

| Error | Condition |
|---|---|
| `UnsupportedTeeType(TEEType actual)` | Not TDX or SNP |
| `UnsupportedBackendType(TEEType teeType, VerificationBackendType backend)` | Invalid verification backend |
| `TeeReportTooShort(uint256 length, uint256 minRequired)` | Generic report is too short |
| `UnsupportedDcapBodyType(uint16 bodyType)` | DCAP output is neither TD10 nor TD15 |
| `DcapReportDataOob(uint256 length, uint256 minRequired)` | DCAP report-data slice is out of bounds |
| `DcapVerificationFailed(bytes output)` | Upstream DCAP verification failed |
| `DcapTcbStatusNotAccepted(uint8 actual)` | DCAP trusted computing base status is 6, 7, or an unknown non-configurable value |
| `InvalidTdxAttributes(bytes8 actual)` | Intel TDX reserved attribute bits are invalid |
| `TdxSeptVeDisableRequired()` | Intel TDX `SEPT_VE_DISABLE` is absent |
| `TdxMigrationServiceTdNotSupported()` | Intel TDX 1.5 `MR_SERVICETD` is nonzero |
| `SnpVerificationFailed(VerificationResult result)` | SNP proof journal reports failure |
| `SnpReportHashMismatch(bytes32 expected, bytes32 actual)` | Raw report is not the proof-bound report |
| `InvalidSnpReportLength(uint256 actual, uint256 expected)` | Raw report is not exactly 1,184 bytes |
| `UnsupportedSnpReportVersion(uint32 actual)` | Report version is unsupported |
| `InvalidSnpPolicy(uint64 actual)` | Required or reserved policy bits are invalid |
| `UnsupportedSnpVmpl(uint32 actual)` | `VMPL` is nonzero |
| `SnpMigrationAgentNotSupported()` | `REPORT_ID_MA` is neither the all-zero nor the all-`0xff` no-association sentinel |
| `InvalidSnpSignatureAlgorithm(uint32 actual)` | Report signature algorithm is not ECDSA P-384 with SHA-384 |
| `InvalidSnpKeySettings(uint32 actual)` | Signing-key selection or masking-chip settings are unsupported |
| `InvalidSnpReservedField(uint256 offset)` | A reserved report field is nonzero |
| `InvalidSnpTcb(uint256 offset, uint64 actual)` | A TCB field has nonzero reserved bytes |
| `InvalidSnpPlatformInfo(uint64 actual)` | `PLATFORM_INFO` contains an unsupported bit |
| `UnsupportedSnpCpuid(uint24 actual)` | CPUID is outside AMD family `0x19`, model `0x00` through `0x1f` |
| `InvalidSnpTcbOrder(bytes32 lower, bytes32 upper)` | TCB fields do not satisfy reported ≤ committed ≤ current, or launch ≤ committed |

---

## SignatureVerifier

**File**: `src/SignatureVerifier.sol`
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

**File**: `src/bases/TpmVerifier.sol`
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

**File**: `src/bases/AkCollateralVerifier.sol`
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
   - top-level `iat`, `nbf`, and `exp` are canonical unsigned 64-bit JSON integers;
     nested fields cannot substitute for them
   - `nbf < exp`, `iat < exp`, `iat <= block.timestamp`, and
     `nbf <= block.timestamp < exp`
   - `x-ms-attestation-type` in `{"tdxvm", "sevsnpvm"}`
   - `x-ms-compliance-status == "azure-compliant-cvm"`
7. Extract the report-data claim (`tdx_report_data` for TDX, `x-ms-sevsnpvm-reportdata` for SNP); hex-decode first 32 bytes as `bindingHash`; assert next 32 bytes decode to zero.
8. Assert `sha256(hclVarData) == bindingHash`.
9. Parse `HCLAkPub` from `hclVarData` using the §14.3-scoped JWK parser, construct `PublicIdentity` with `typeId = ALGO_ID_RS256`.

The verifier maps `x-ms-attestation-type` to the returned `teeType`
(`tdxvm` → `IntelTDX`, `sevsnpvm` → `AmdSevSnp`). `SessionRegistry` requires
this value to equal `TeeVerificationResult.teeType`.

Binding: `sha256(hclVarData)` is returned as `bindingHash`. `SessionRegistry`
requires the verified Intel TDX or AMD SEV-SNP report's 64-byte `REPORT_DATA`
to equal `bindingHash || bytes32(0)`. This joins the independently verified raw
TEE report to the MAA-signed HCL data and prevents report splicing.

#### GcpCertChain
GCP provides X.509 certificate chain:
1. ABI-decode `bytes[]` array of DER certificates from collateral data
2. Call `tpmAttestation.verifyCertChain(certs)` → returns `CertPubkey`
3. Convert `CertPubkey` → `PublicIdentity`

Binding: `bindingHash = bytes32(0)`. AK is bound to TEE via PCR15 computation (verified in SessionRegistry step 7).

### Errors

| Error | Condition |
|---|---|
| `UnsupportedAkCollateralType(AkPubCollateralType actual)` | Unknown collateral type |
| `AzureJwkParsingFailed()` | `HCLAkPub` JWK field extraction from `hclVarData` failed |
| `MaaJwtMalformed()` | JWT does not split into three base64url parts, or header/claims fail base64url/JSON decode |
| `MaaJwtAlgUnsupported()` | JWT header `alg` is not `"RS256"` |
| `MaaJwtHeaderClaimMissing()` | JWT header is missing `kid` or `alg` |
| `MaaJwtClaimMissing()` | JWT claims is missing a required field |
| `MaaJwtNumericClaimMalformed(bytes32 fieldNameHash)` | `iat`, `nbf`, or `exp` is not a canonical unsigned 64-bit JSON integer |
| `MaaJwtValidityWindowInvalid(uint64 issuedAt, uint64 notBefore, uint64 expiresAt)` | `nbf >= exp` or `iat >= exp` |
| `MaaJwtNotYetValid(uint64 notBefore, uint256 verificationTime)` | `block.timestamp < nbf` |
| `MaaJwtExpired(uint64 expiresAt, uint256 verificationTime)` | `block.timestamp >= exp` |
| `MaaJwtIssuedInFuture(uint64 issuedAt, uint256 verificationTime)` | `block.timestamp < iat` |
| `MaaKidNotRegistered(bytes32 kidHash)` | `kidHash` lookup in MAA Signing Key Registry returned an empty / revoked / expired key |
| `MaaJwtIssuerMismatch(bytes32 actual, bytes32 expected)` | `iss` claim hash does not equal `key.issuerHash` |
| `MaaJwtComplianceFailed()` | `x-ms-compliance-status` ≠ `"azure-compliant-cvm"`, or `x-ms-attestation-type` ∉ `{"tdxvm","sevsnpvm"}` |
| `MaaJwtReportDataMalformed()` | report_data claim has wrong length, non-hex chars, or non-zero padding |
| `MaaJwtSignatureInvalid(bytes32 kidHash)` | `signatureVerifier.verify` rejected the RS256 signature over `header || "." || claims` |
| `MaaJwtBindingMismatch()` | `sha256(hclVarData)` did not equal the report-data claim prefix |

---

## TpmBase

**File**: `src/bases/TpmBase.sol`
**Role**: Shared abstract base holding `ITpmAttestation` immutable

```solidity
abstract contract TpmBase {
    ITpmAttestation public immutable tpmAttestation;
    constructor(ITpmAttestation _tpmAttestation) {
        tpmAttestation = _tpmAttestation;
    }
}
```

`TpmVerifier` and `AkCollateralVerifier` each inherit `TpmBase`.
`SessionRegistry` inherits `TpmVerifier` and calls a separately deployed
`IAkCollateralVerifier`; it does not inherit `AkCollateralVerifier`. Each
constructor receives its own immutable `ITpmAttestation` reference. A
deployment may point both references at the same `ITpmAttestation` contract.
