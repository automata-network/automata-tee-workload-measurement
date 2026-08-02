# CVM Registry Contracts -- Architecture Overview

**Source**: repository root
**Framework**: Foundry

## High-Level Architecture

Three-tier on-chain registry establishing cryptographic chains of trust from TEE hardware to verifiable CVM session identities.

```
┌─────────────────────────────────────────────────────────────┐
│                    SessionRegistry                          │
│       (attestation verification and session lifecycle)      │
│   Merges policies from both registries below, verifies     │
│   TEE + TPM evidence, creates time-bounded sessions        │
├──────────────────────────┬──────────────────────────────────┤
│   BaseImageRegistry      │      WorkloadRegistry            │
│   (OS/platform layer)    │      (application layer)         │
│   Platform PCR policies  │      Workload PCR policies       │
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
     │ (separate TPM       │      │ (fingerprint    │
     │  quote/certify)     │      │  directory)     │
     └─────────┬───────────┘      └─────────────────┘
               │ external
        AkCollateralVerifier ── MaaKeyRegistry
               │
        ZkVerifierRegistry
```

## Core Design Principles

1. **Fingerprint-based ownership** -- All ownership via `keccak256(KEY_DOMAIN || typeId || key)`, NOT EVM addresses. Enables TEE-managed keys to own registry entries directly.

2. **Signature-verified operations** -- No `msg.sender` checks. Owner operations require off-chain signatures. Anyone can submit a valid signature on behalf of the owner. Prevents address-based front-running; enables intent-based access control.

3. **Policy hierarchy** -- Platform invariants and machine-specific variant
overrides are merged at session registration time. By convention, a base image
defines platform PCR policy and a workload defines workload PCR policy. The
contracts require sorted PCR indexes below 24 but do not enforce a fixed
platform-versus-workload index split.

4. **Verified TEE policy** -- `TeeVerifier` extracts signed security state.
`AmdSnpSecurityPolicyRegistry` stores per-CPUID AMD defaults and evaluates TEE
and metadata attributes. An explicit value replaces a default on its policy
side; the registry value is not an independent mandatory floor.

5. **UUPS upgradeable registries** -- `BaseImageRegistry`, `WorkloadRegistry`,
`SessionRegistry`, `ZkVerifierRegistry`, `AmdSnpSecurityPolicyRegistry`, and
`KeyResolver` use the UUPS proxy pattern with storage gaps.

6. **Nonce-based replay protection** -- Per-owner nonce in SessionRegistry, bound into TPM quote `extraData`.

7. **Polymorphic verification backends** -- Solidity (on-chain), ZK RiscZero, ZK Succinct. TEE verification can be offloaded to ZK proofs.

## Directory Structure

```
src/
├── BaseImageRegistry.sol
├── WorkloadRegistry.sol
├── SessionRegistry.sol
├── ZkVerifierRegistry.sol
├── AmdSnpSecurityPolicyRegistry.sol
├── KeyResolver.sol
├── MaaKeyRegistry.sol             (per-region MAA signing keys for AzureMaaJwt)
├── TeeVerifier.sol
├── SignatureVerifier.sol
├── bases/
│   ├── TpmBase.sol
│   ├── TpmVerifier.sol
│   └── AkCollateralVerifier.sol   (MAA JWT + GCP cert chain verification)
├── interfaces/
│   ├── IAkCollateralVerifier.sol
│   ├── ISignatureVerifier.sol
│   ├── ITeeVerifier.sol
│   ├── registries/
│   │   ├── IAmdSnpSecurityPolicyRegistry.sol
│   │   ├── IBaseImageRegistry.sol
│   │   ├── IWorkloadRegistry.sol
│   │   ├── ISessionRegistry.sol
│   │   ├── IZkVerifierRegistry.sol
│   │   ├── IKeyResolver.sol
│   │   └── IMaaKeyRegistry.sol
│   ├── external/
│       ├── IDcapAttestation.sol   (Intel DCAP)
│       ├── ISnpAttestation.sol    (AMD SNP)
│       └── INitroEnclaveVerifier.sol
│   └── zk/
│       └── IZkVerifierAdapters.sol
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
├── zk/
│   └── ZkVerifierAdapters.sol     (typed Intel TDX, AMD SEV-SNP, TPM Quote, and AWS NitroTPM adapters)
└── mock/
    ├── MockTpmAttestation.sol
    ├── MockSignatureVerifier.sol
    ├── MockAutomataDcapAttestation.sol
    └── MockAutomataSnpAttestation.sol
```

## Contract Dependency Graph

```
SessionRegistry
  ├── inherits: ISessionRegistry, OwnableUpgradeable, UUPSUpgradeable
  ├── immutable refs: ITeeVerifier, TpmVerifier, IAkCollateralVerifier,
  │                   ISignatureVerifier, IBaseImageRegistry, IWorkloadRegistry,
  │                   and IAmdSnpSecurityPolicyRegistry
  └── uses: LibKey and LibBytes

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
  ├── immutable refs: IDcapAttestation, IZkVerifierRegistry
  └── resolves Intel TDX and AMD SEV-SNP ZK adapters by exact program identifier

AmdSnpSecurityPolicyRegistry
  ├── inherits: IAmdSnpSecurityPolicyRegistry, OwnableUpgradeable, UUPSUpgradeable
  └── uses: AmdSnpPolicy

SignatureVerifier
  ├── inherits: ISignatureVerifier
  └── uses: OZ RSA, OZ ECDSA, P256Verifier (external), Asn1Decode

KeyResolver
  ├── inherits: IKeyResolver, OwnableUpgradeable, UUPSUpgradeable
  └── uses: LibKey

MaaKeyRegistry
  ├── inherits: IMaaKeyRegistry, OwnableUpgradeable, UUPSUpgradeable
  └── stores: per-region Microsoft Azure Attestation signing keys (RS256 / RSA-2048)
              consumed by AkCollateralVerifier when verifying AzureMaaJwt collateral

TpmVerifier
  ├── inherits: TpmBase
  ├── immutable ref: IZkVerifierRegistry
  └── verifies raw Solidity TPM Quotes, `tpm_quote.v1` proofs, and TPM Certify evidence

AkCollateralVerifier
  ├── implements: IAkCollateralVerifier; inherits: TpmBase
  ├── immutable refs: IMaaKeyRegistry, ISignatureVerifier, IZkVerifierRegistry
  └── verifies Azure MAA JWT, GCP certificate-chain, and `aws_nitrotpm.v1` evidence

ZkVerifierRegistry
  ├── inherits: IZkVerifierRegistry, OwnableUpgradeable, UUPSUpgradeable
  └── maps one exact proof type, backend, and program identifier to one verifier adapter

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
message = sha256(abi.encode(MSG_SEPARATOR, block.chainid, address(this), opExpiresAt, ...params))
```

## Deployment status

The verified TEE attribute implementation adds
`AmdSnpSecurityPolicyRegistry` and changes the immutable dependencies of
`SessionRegistry`. It is not the deployment recorded by the older address
snapshot in `deployment/560048.json`. Do not treat addresses in that file as a
deployment of this feature. Verify the active implementation and every
immutable dependency from live chain state before an upgrade.

## TEE Platform Support

| TEE | Cloud | AK Binding | PCR15 Binding |
|---|---|---|---|
| Intel TDX | Azure | MAA-signed JWT (RS256); `tdx_report_data` claim commits to `sha256(hclVarData)`; JWT signature verified against per-region MAA RSA-2048 key from MaaKeyRegistry | N/A |
| AMD SEV-SNP | Azure | MAA-signed JWT (RS256); `x-ms-sevsnpvm-reportdata` claim commits to `sha256(hclVarData)`; same per-region MAA key signs both TDX and SNP paths | N/A |
| Intel TDX | GCP | Certificate chain via `ITpmAttestation.verifyCertChain` | `sha256(bytes32(0) || bytes16(0) || UUID)`; RTMR3 = `sha384(bytes48(0) || bytes32(0) || UUID)` |
| AMD SEV-SNP | GCP | Certificate chain | `sha256(bytes32(0) || report_id)` |
| AMD SEV-SNP | AWS | `aws_nitrotpm.v1` `AwsNitroTpmProof` | SHA-384 PCR15 joins the Quote and NitroTPM document; `Sha256AndSha384` also binds SHA-256 PCR15 to `REPORT_ID` |

For Azure TDX and Azure SEV-SNP, `_verifyAzureAkCollateral` returns the
MAA-signed `sha256(hclVarData)` as `bindingHash`. `_verifyProviderEvidence` then
requires the independently verified raw TEE report's `REPORT_DATA` to equal
`bindingHash || bytes32(0)`. Azure does not use PCR15 for this binding.

## Signature Algorithm Support

| ID | Name | Key Format | Signature Format |
|---|---|---|---|
| 0 | NULL | -- | -- |
| 1 | RS256 | DER PKCS#1 RSA public key | Raw RSA signature |
| 2 | ES256 | 65-byte SEC1 uncompressed P-256 | DER-encoded (r, s) |
| 3 | ES256K | 65-byte SEC1 uncompressed secp256k1 | 65-byte Ethereum (r, s, v) |
