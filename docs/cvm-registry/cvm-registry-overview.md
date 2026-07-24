# CVM Registry Contracts -- Architecture Overview

**Source**: `~/work/automata-tee-workload-measurement/`
**Total**: ~5,487 lines of Solidity across 30 source files
**Framework**: Foundry

## High-Level Architecture

Three-tier on-chain registry establishing cryptographic chains of trust from TEE hardware to verifiable CVM session identities.

```
┌─────────────────────────────────────────────────────────────┐
│                    SessionRegistry                          │
│         (orchestrator: 9-step attestation pipeline)         │
│   Merges policies from both registries below, verifies     │
│   TEE + TPM evidence, creates time-bounded sessions        │
├──────────────────────────┬──────────────────────────────────┤
│   BaseImageRegistry      │      WorkloadRegistry            │
│   (OS/platform layer)    │      (application layer)         │
│   PCR 0-19 policies      │      PCR 20-23 policies          │
│   Platform profiles +    │      Base image access control   │
│   machine variants       │      Attribute requirements      │
└──────────┬───────────────┴──────────────┬───────────────────┘
           │                              │
     ┌─────┴──────┐              ┌────────┴────────┐
     │ TeeVerifier │              │SignatureVerifier│
     │ (DCAP/SNP)  │              │(RS256/ES256/K)  │
     └─────────────┘              └─────────────────┘
           │                              │
     ┌─────┴──────────────┐      ┌────────┴────────┐
     │ TpmVerifier         │      │  KeyResolver    │
     │ AkCollateralVerifier│      │ (fingerprint    │
     │ (TPM quote/certify) │      │  directory)     │
     └─────────────────────┘      └─────────────────┘
```

## Core Design Principles

1. **Fingerprint-based ownership** -- All ownership via `keccak256(KEY_DOMAIN || typeId || key)`, NOT EVM addresses. Enables TEE-managed keys to own registry entries directly.

2. **Signature-verified operations** -- No `msg.sender` checks. Owner operations require off-chain signatures. Anyone can submit a valid signature on behalf of the owner. Prevents address-based front-running; enables intent-based access control.

3. **Policy hierarchy** -- Platform invariants + machine-specific variant overrides, merged at session registration time. BaseImage provides PCR 0-19, Workload provides PCR 20-23.

4. **Stateless verifiers** -- `TeeVerifier` and `SignatureVerifier` are immutable, stateless, shared across registries. No storage, no upgrades needed.

5. **UUPS upgradeable registries** -- `BaseImageRegistry` (gap=46), `WorkloadRegistry` (gap=47), `SessionRegistry` (gap=47), `KeyResolver` (gap=49) all use UUPS proxy pattern with storage gaps.

6. **Nonce-based replay protection** -- Per-owner nonce in SessionRegistry, bound into TPM quote `extraData`.

7. **Polymorphic verification backends** -- Solidity (on-chain), ZK RiscZero, ZK Succinct. TEE verification can be offloaded to ZK proofs.

## Directory Structure

```
src/
├── BaseImageRegistry.sol          (525 lines)
├── WorkloadRegistry.sol           (305 lines)
├── SessionRegistry.sol            (1,312 lines)
├── KeyResolver.sol                (102 lines)
├── MaaKeyRegistry.sol             (per-region MAA signing keys for AzureMaaJwt)
├── TeeVerifier.sol                (298 lines)
├── SignatureVerifier.sol          (172 lines)
├── bases/
│   ├── TpmBase.sol                (30 lines)
│   ├── TpmVerifier.sol            (197 lines)
│   └── AkCollateralVerifier.sol   (MAA JWT + GCP cert chain verification)
├── interfaces/
│   ├── ISignatureVerifier.sol
│   ├── ITeeVerifier.sol
│   ├── registries/
│   │   ├── IBaseImageRegistry.sol
│   │   ├── IWorkloadRegistry.sol
│   │   ├── ISessionRegistry.sol
│   │   ├── IKeyResolver.sol
│   │   └── IMaaKeyRegistry.sol
│   └── external/
│       ├── IDcapAttestation.sol   (Intel DCAP)
│       ├── ISnpAttestation.sol    (AMD SNP)
│       └── INitroEnclaveVerifier.sol (AWS Nitro, not yet integrated)
├── types/
│   ├── Common.sol                 (core data structures)
│   ├── Evidence.sol               (attestation evidence types)
│   └── Constants.sol              (domain separators, algo IDs)
├── lib/
│   ├── LibKey.sol                 (key fingerprinting & conversion)
│   ├── LibBytes.sol               (Bytes48/64 utilities)
│   ├── Sha2Ext.sol                (SHA-384/512)
│   ├── Asn1Decode.sol             (ASN.1 DER parsing)
│   └── BytesUtils.sol             (byte string utilities)
└── mock/
    ├── MockTpmAttestation.sol
    ├── MockSignatureVerifier.sol
    ├── MockAutomataDcapAttestation.sol
    └── MockAutomataSnpAttestation.sol
```

## Contract Dependency Graph

```
SessionRegistry
  ├── inherits: TpmVerifier, AkCollateralVerifier, OwnableUpgradeable, UUPSUpgradeable
  ├── immutable refs: ITeeVerifier, ISignatureVerifier, IBaseImageRegistry,
  │                   IWorkloadRegistry, IMaaKeyRegistry
  └── uses: LibKey, LibBytes, Sha2Ext, BytesUtils

BaseImageRegistry
  ├── inherits: IBaseImageRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable
  ├── immutable ref: ISignatureVerifier
  └── uses: LibKey

WorkloadRegistry
  ├── inherits: IWorkloadRegistry, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable
  ├── immutable ref: ISignatureVerifier
  └── uses: LibKey

TeeVerifier
  ├── inherits: ITeeVerifier
  ├── immutable refs: IDcapAttestation, ISnpAttestation
  └── uses: LibBytes, BytesUtils

SignatureVerifier
  ├── inherits: ISignatureVerifier
  └── uses: OZ RSA, OZ ECDSA, P256Verifier (external), Asn1Decode

KeyResolver
  ├── inherits: IKeyResolver, OwnableUpgradeable, UUPSUpgradeable
  └── uses: LibKey

MaaKeyRegistry
  ├── inherits: IMaaKeyRegistry, OwnableUpgradeable, UUPSUpgradeable
  ├── immutable ref: ISignatureVerifier
  └── stores: per-region Microsoft Azure Attestation signing keys (RS256 / RSA-2048)
              consumed by AkCollateralVerifier when verifying AzureMaaJwt collateral

TpmVerifier (abstract)
  ├── inherits: TpmBase
  └── uses: LibKey

AkCollateralVerifier (abstract)
  ├── inherits: TpmBase
  ├── immutable ref: IMaaKeyRegistry
  ├── virtual: _signatureVerifier() (overridden by SessionRegistry)
  └── uses: LibString, Base64 (Solady)

TpmBase (abstract)
  └── holds: ITpmAttestation immutable
```

## PCR Evaluation Modes

| Mode | Semantics |
|---|---|
| `STATIC` | Exact match: `actual == expected` |
| `DYNAMIC_SUBSET` | Every `matchData` hash must appear in the PCR events (order irrelevant; extra events permitted) |
| `DYNAMIC_SUBSEQUENCE` | `matchData` values must appear as subsequence in PCR events (order matters) |

## ID Derivation Scheme

All registry IDs are deterministic keccak256 hashes with domain separation.
NOTE: All use `abi.encode` (not `encodePacked`).

| Entity | Formula |
|---|---|
| Key fingerprint | `keccak256(abi.encode(KEY_DOMAIN, typeId, key))` |
| Base image ID | `keccak256(abi.encode(BASEIMAGE_DOMAIN, name, version))` -- NO ownerFingerprint |
| Platform profile ID | `keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, profileName))` |
| Variant ID | `keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, variantName))` |
| Workload ID | `keccak256(abi.encode(WORKLOAD_DOMAIN, name, version))` -- NO ownerFingerprint |
| Session ID | `keccak256(abi.encode(SESSION_DOMAIN, tpmSignatureHash, teeReportBytesHash))` |

## Message Signing Convention

All owner-signed messages use **sha256** (NOT keccak256) and include **chainid + address(this)** for replay protection:
```
message = sha256(abi.encode(MSG_SEPARATOR, block.chainid, address(this), expireAt, ...params))
```

## Deployment (Hoodi Testnet)

| Contract | Address |
|---|---|
| SessionRegistry | `0xD1860020870ffEd23a644d0CD4CA9E7b3Ff53D6c` |
| BaseImageRegistry | `0x15A8F7A012b2dBad3fAD6020a0dF1F81E86F6171` |
| WorkloadRegistry | `0xFA8Eb822594d7aA7221aBE3Cd7f3F17c3F16bA9E` |
| TeeVerifier | `0x80c17Fb23a7f747174DCD29Ec94B8D5a7227F266` |
| SignatureVerifier | `0x996eB4a6E1FEbF1788B027FA990643B2328A5E72` |
| KeyResolver | `0x74Ee5a4c6e9207cFDa2Bb28E79bf97CcA42F18E4` |

## TEE Platform Support

| TEE | Cloud | AK Binding | PCR15 Binding |
|---|---|---|---|
| Intel TDX | Azure | MAA-signed JWT (RS256); `tdx_report_data` claim commits to `sha256(hclVarData)`; JWT signature verified against per-region MAA RSA-2048 key from MaaKeyRegistry | N/A |
| AMD SEV-SNP | Azure | MAA-signed JWT (RS256); `x-ms-sevsnpvm-reportdata` claim commits to `sha256(hclVarData)`; same per-region MAA key signs both TDX and SNP paths | N/A |
| Intel TDX | GCP | Certificate chain via `ITpmAttestation.verifyCertChain` | `sha256(bytes32(0) || bytes16(0) || UUID)`; RTMR3 = `sha384(bytes48(0) || bytes32(0) || UUID)` |
| AMD SEV-SNP | GCP | Certificate chain | `sha256(bytes32(0) || report_id)` |

For Azure TDX and Azure SEV-SNP, `_verifyAzureAkCollateral` returns the
MAA-signed `sha256(hclVarData)` as `bindingHash`. `_verifyTeeAkBinding` then
requires the independently verified raw TEE report's `REPORT_DATA` to equal
`bindingHash || bytes32(0)`. Azure does not use PCR15 for this binding.

## Signature Algorithm Support

| ID | Name | Key Format | Signature Format |
|---|---|---|---|
| 0 | NULL | -- | -- |
| 1 | RS256 | DER PKCS#1 RSA public key | Raw RSA signature |
| 2 | ES256 | 65-byte SEC1 uncompressed P-256 | DER-encoded (r, s) |
| 3 | ES256K | 65-byte SEC1 uncompressed secp256k1 | 65-byte Ethereum (r, s, v) |
