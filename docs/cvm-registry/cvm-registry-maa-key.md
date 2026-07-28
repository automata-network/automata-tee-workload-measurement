# MaaKeyRegistry -- Detailed Analysis

**File**: `src/MaaKeyRegistry.sol`
**Interface**: `src/interfaces/registries/IMaaKeyRegistry.sol`
**Role**: Admin-managed directory of Microsoft Azure Attestation (MAA) signing keys consumed by `AkCollateralVerifier` when verifying `AzureMaaJwt` AK collateral. Distinct from `KeyResolver`: stores PKCS#1 RSA pubkeys with issuer + validity + revocation metadata, not `PublicIdentity` fingerprints.

## Inheritance

```
IMaaKeyRegistry
OwnableUpgradeable
UUPSUpgradeable
```

Not `PausableUpgradeable`. Upsert/revoke are gated by `onlyOwner`; the EVM tx nonce supplies replay protection (no off-chain signed envelope).

## Storage

| Variable | Type | Purpose |
|---|---|---|
| `_keys` | `mapping(bytes32 => MaaSigningKey)` | `kidHash` → signing key record |
| `__gap` | `uint256[49]` | Storage gap for upgrades |

## Data Model

```solidity
struct MaaSigningKey {
    bytes pkcs1Pubkey;     // DER PKCS#1 RSAPublicKey; ~270 bytes for RSA-2048
    bytes32 issuerHash;    // keccak256(bytes(jwt.claims.iss))
    uint64 notAfter;       // Unix seconds; from the leaf cert NotAfter
    bool revoked;
}
```

Empty record (`pkcs1Pubkey.length == 0 && !revoked`) means the kid is not registered.

### Field semantics

- **`kidHash`** = `keccak256(bytes(jwt.header.kid))`. The MAA JWKS (`<endpoint>/certs`) lists one or more keys per region; each has a `kid` string (Microsoft uses 44-char base64url SHA-256 thumbprints). Lookup is by `keccak256(bytes(kid))`, not by region.
- **`pkcs1Pubkey`** = DER PKCS#1 `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`). This is the *inner* RSA key blob, not the X.509 `SubjectPublicKeyInfo` wrapper. `SignatureVerifier._verifyRsa` consumes the same shape.
- **`issuerHash`** = `keccak256(bytes(jwt.claims.iss))`. The string MUST equal the `iss` claim emitted by MAA byte-for-byte. For the shared eastus pool that is `https://sharedeus.eus.attest.azure.net` (full host, no trailing slash). Custom tenant endpoints take the form `https://<tenant>.<region>.attest.azure.net`. The struct-doc shorthand `"https://<region>.attest.azure.net"` in `IMaaKeyRegistry.sol:10` is abbreviated; always trust the live JWT `iss`.
- **`notAfter`** = leaf X.509 `NotAfter` as Unix seconds. MAA rotates RSA-2048 signing certs ~2 months before expiry, so a fresh upsert typically lands a `notAfter` 10-14 months out.

## Functions

### `upsertMaaSigningKey`

```solidity
function upsertMaaSigningKey(
    bytes32 kidHash,
    bytes calldata pkcs1Pubkey,
    bytes32 issuerHash,
    uint64 notAfter
) external onlyOwner;
```

- Owner-only.
- Validates: `pkcs1Pubkey` non-empty, `issuerHash != bytes32(0)`, `notAfter >= block.timestamp` (boundary inclusive).
- Overwrites any existing record at `kidHash` and resets `revoked = false`.
- Emits `MaaSigningKeyUpserted(kidHash, issuerHash, notAfter)`.

### `revokeMaaSigningKey`

```solidity
function revokeMaaSigningKey(bytes32 kidHash) external onlyOwner;
```

- Owner-only.
- Reverts `KidNotRegistered` if the kid was never registered (empty `pkcs1Pubkey`).
- Sets `revoked = true`. Subsequent JWT verifications under this kid revert `MaaKidNotRegistered` regardless of `notAfter`.
- Emits `MaaSigningKeyRevoked(kidHash)`.

### `getMaaSigningKey` / `hasMaaSigningKey`

```solidity
function getMaaSigningKey(bytes32 kidHash) external view returns (MaaSigningKey memory);
function hasMaaSigningKey(bytes32 kidHash) external view returns (bool);
```

`getMaaSigningKey` returns the empty struct (not a revert) for unregistered kids — same shape as `KeyResolver.getIdentity` would deserve, but no `NotFound` revert; callers must inspect `pkcs1Pubkey.length`. `hasMaaSigningKey` returns `pkcs1Pubkey.length != 0 && !revoked` and does **not** check `notAfter` — time-window enforcement is the verifier's responsibility because `block.timestamp` is not meaningful for some callers.

## Errors

| Error | Condition |
|---|---|
| `EmptyPubkey()` | `pkcs1Pubkey.length == 0` on upsert |
| `EmptyIssuerHash()` | `issuerHash == bytes32(0)` on upsert |
| `NotAfterInPast(uint64 notAfter, uint64 nowTs)` | `notAfter < block.timestamp` on upsert |
| `KidNotRegistered(bytes32 kidHash)` | `revokeMaaSigningKey` on a kid that was never upserted |

## Verifier Integration

`AkCollateralVerifier._verifyAzureAkCollateral` (`src/bases/AkCollateralVerifier.sol`) consumes the registry exactly once per AK-collateral verification:

```solidity
bytes32 kidHash = keccak256(bytes(kid));
MaaSigningKey memory key = maaKeyRegistry.getMaaSigningKey(kidHash);
if (key.pkcs1Pubkey.length == 0 || key.revoked || block.timestamp > key.notAfter) {
    revert MaaKidNotRegistered(kidHash);
}
// ... RS256 verify(headerB64 || "." || claimsB64) under key.pkcs1Pubkey ...
bytes32 actualIssuerHash = keccak256(bytes(iss));
if (actualIssuerHash != key.issuerHash) {
    revert MaaJwtIssuerMismatch(actualIssuerHash, key.issuerHash);
}
// Top-level iat, nbf, and exp are required; nested fields cannot substitute.
// The same block.timestamp also enforces:
// nbf < exp, iat < exp, iat <= block.timestamp, and
// nbf <= block.timestamp < exp.
```

Failure mapping:

| Verifier revert | Registry state |
|---|---|
| `MaaKidNotRegistered(bytes32 kidHash)` | kid never upserted, revoked, or past `notAfter` |
| `MaaJwtIssuerMismatch(bytes32 actual, bytes32 expected)` | kid registered but `issuerHash` was computed over the wrong string |
| `MaaJwtSignatureInvalid(bytes32 kidHash)` | `pkcs1Pubkey` does not match the cert MAA actually signed with |

`MaaKidNotRegistered` is the canonical "we missed a rotation" signal; an off-chain watcher should treat it as a pageable condition.

## Trust Model

The owner of `MaaKeyRegistry` is the root of trust for the entire Azure-CVM attestation path on a deployment. A compromised owner can upsert an attacker-controlled RSA key under Microsoft's `kid` and sign forged JWTs that the on-chain verifier will accept, breaking the trust chain end-to-end for every Azure session ever registered against this `SessionRegistry` deployment.

Operational implications:

- The owner key **must** be a multisig / hardware-custody arrangement. The contract code intentionally does not impose this; it is left to the deployment owner.
- A separate, lower-privilege "rotation operator" role does not exist — every upsert is a full owner operation. Rotation tooling should call the multisig, not a hot key.
- Pause behavior is not provided. If a key is suspected compromised, `revokeMaaSigningKey` is the only on-chain mitigation; pending JWTs signed under that kid will fail immediately.

## Off-Chain Sourcing

The contract holds the registry. Fetching the right values into the registry is off-chain work and is **not** done by any tool in this repo today; the `script/DeployMaaKeyRegistry.s.sol` script deploys the contract but does not seed it.

For each MAA region the deployment needs to support:

1. **Pick the endpoint.** The portal hard-codes `AZURE_MAA_REGION_DEFAULT = "eus"` (`atakit-portal/crates/atakit-portal-api/src/chain_submission.rs`), so eastus is the minimum. The shared pool is `https://sharedeus.eus.attest.azure.net`. Microsoft publishes the full table of 59 public-cloud endpoints in `Azure/cvm-attestation-tools::attestation_uri_table.json`; the pattern is `https://shared<region>.<region>.attest.azure.net` for shared pools and `https://<tenant>.<region>.attest.azure.net` for custom tenants.

2. **Fetch JWKS.** `GET <endpoint>/certs` returns a JSON document with a `keys` array. Each entry has `kid`, `kty: "RSA"`, `alg: "RS256"`, plus either JWK `n`/`e` fields or an `x5c` cert chain. MAA includes both; `x5c[0]` is the leaf cert.

   **Not every JWKS entry is a JWT-signing key.** A shared-pool JWKS (e.g. `sharedeus.eus.attest.azure.net/certs`) typically contains four kinds of entry:

   - **Self-signed RSA-2048 `CN=<endpoint>` certs** — these are what the shared pool actually signs attestation JWTs with. Usually 1-2 of them at a time (current + next-up after rotation).
   - **Self-signed RSA-1024 `CN=<endpoint>` certs** — legacy keys retained for historic verification. Modern MAA does not emit JWTs under these. Never register.
   - **Microsoft-chained "Microsoft Azure Attestation 2020" cert** — issued by `Microsoft Azure Attestation PCA 2019`, used by **tenant-mode** MAA instances (custom endpoints customers deploy themselves), not by the shared pool. Registering this on a deployment that only consumes shared-pool JWTs grants signing trust to a key the shared pool will never emit JWTs under — strict net loss.

   The selection rule for shared-pool deployments: **self-signed, RSA ≥ 2048**. For tenant-mode deployments: any leaf with RSA ≥ 2048 (the chained Microsoft cert is the JWT-signer there). The `maa-key-registrar` tool's `--include {self-signed,any,all}` flag encodes exactly this distinction.

3. **Derive the four args.**
   - `kidHash = keccak256(bytes(kid))`.
   - `pkcs1Pubkey = DER PKCS#1 RSAPublicKey`. Two ways to get it:
     - From `x5c[0]`: base64-decode the leaf cert, parse the X.509 `SubjectPublicKeyInfo`, strip the `AlgorithmIdentifier` and BIT STRING wrapper, and emit the inner `SEQUENCE { INTEGER n, INTEGER e }`. This is also what binds `notAfter` to the same cert.
     - From `n`/`e`: base64url-decode each, build the PKCS#1 `SEQUENCE` by hand. Convenient but you still need `x5c[0]` for `notAfter`.
   - `issuerHash = keccak256(bytes(<iss>))` where `<iss>` is the exact string the MAA JWT puts in its `iss` claim. For the shared pool, this is the endpoint URL (e.g. `https://sharedeus.eus.attest.azure.net`); verify by attesting once against the endpoint and reading the JWT `iss` claim — do not assume.
   - `notAfter = leafCert.tbsCertificate.validity.notAfter` as Unix seconds.

4. **Submit.** `cast send <MaaKeyRegistry> 'upsertMaaSigningKey(bytes32,bytes,bytes32,uint64)' <kidHash> <pkcs1Pubkey> <issuerHash> <notAfter>` from the owner. For multi-key rotations, batch via a multisig executor.

Reference implementation: [`crates/maa-key-registrar`](../../crates/maa-key-registrar/). Subcommands `derive` / `status` / `sync` / `revoke` automate steps 2-4. `sync --dry-run` prints `cast send` lines for multisig submission; `sync` (with a hot owner key) broadcasts directly.

## Key Rotation

Microsoft policy: a fresh MAA RSA-2048 signing cert appears in `/certs` ~2 months before the previous one expires, and both kids overlap in the JWKS during the transition. Concretely:

- New kids appear silently. Without monitoring, the first warning that rotation happened is `MaaKidNotRegistered` reverts when the old kid drops out.
- The registry supports overlap natively — upsert the new kid (without revoking the old one) the moment it appears in JWKS, then let the old kid age out via `notAfter`. No service window.
- Microsoft does not publish an explicit rotation schedule. A polling watcher is the only reliable signal.

Recommended off-chain watcher behaviour:

1. Every N minutes (suggested 30-60), `GET <endpoint>/certs` for every region you support.
2. Compute `kidHash` for each key in the response. Compare against the on-chain registry via `hasMaaSigningKey`.
3. Any new kid → submit `upsertMaaSigningKey`. Any on-chain kid no longer in JWKS and past `notAfter` → no action needed (verifier will reject naturally). Suspected compromise → `revokeMaaSigningKey` immediately.
4. Page on: JWKS fetch failure for > 24h, any registered kid that is < 7 days from `notAfter` and no successor has appeared.

Revocation is not sticky. `upsertMaaSigningKey` always writes
`revoked = false`. The current `maa-key-registrar sync` command calls
`hasMaaSigningKey`, which returns `false` for a revoked kid, classifies that kid
as missing, and upserts it again if it remains in JWKS. After an emergency
revocation, stop automated `sync` for that endpoint or add an operator-side
denylist until the revoked kid disappears from JWKS. A safer registrar should
represent `revoked` as a separate state and require an explicit operation to
restore it.

The watcher is intentionally out of scope for the contract repo and the portal repo. It is operator infrastructure; treat it the same way you would treat a CA-cert renewal cron job.

## Pre-Deployment Checklist

Before any Azure CVM can register against a new `SessionRegistry` deployment:

- [ ] `MaaKeyRegistry` proxy deployed (`script/DeployMaaKeyRegistry.s.sol`).
- [ ] `AkCollateralVerifier` immutable `IMaaKeyRegistry` reference points to that proxy.
- [ ] `SessionRegistry` immutable `IAkCollateralVerifier` reference points to that verifier.
- [ ] Owner of `MaaKeyRegistry` is the production multisig (not a hot key, not the EOA that ran `forge script`).
- [ ] At least the eastus shared-pool kid(s) currently advertised at `https://sharedeus.eus.attest.azure.net/certs` are upserted. Verify with `hasMaaSigningKey` and by attesting a real Azure CVM once and confirming `chain submit` succeeds end-to-end.
- [ ] Watcher (or equivalent calendar reminder) is in place to catch rotation.

Failure mode without these: every Azure CVM `chain submit` aborts at `MaaKidNotRegistered`, and the portal classifies it as a transient `OrchError::Maa` and retries forever. The CVM never reaches `ChainStatus::Registered`.

## Design Notes

- **Per-region knob is intentionally absent.** `AkCollateralVerifier` holds a single `IMaaKeyRegistry` immutable reference; there is no per-region routing on chain. Different regions' kids coexist in the same mapping. The portal-side region selector (`AZURE_MAA_REGION_DEFAULT`) only decides *which* MAA endpoint signs the JWT; the on-chain side simply looks up whichever kid is in the JWT header.
- **No event-replay for state reconstruction.** Unlike `KeyResolver` (which is idempotent and re-emission-free), `MaaSigningKeyUpserted` is emitted on every upsert including overwrites. Indexers tracking the current set must take the last event per `kidHash`, not the first.
- **No issuer-to-region map.** The contract does not enforce that a given kid only verifies JWTs from a specific MAA endpoint URL beyond the `issuerHash` field; if an admin upserts the same kid with two different issuer strings (sequentially, since the mapping is keyed only by `kidHash`), only the latest survives. This is intentional — MAA reuses `kid` strings only within a single endpoint, so collisions are not expected.
- **`notAfter` is inclusive on both upsert and verify.** `upsertMaaSigningKey`
  accepts `notAfter == block.timestamp`, and the verifier also accepts that
  exact timestamp because it rejects only when
  `block.timestamp > key.notAfter`. The key becomes invalid when the block
  timestamp advances past `notAfter`; there is no boundary mismatch.

## Relationship to Other Contracts

- **`AkCollateralVerifier`** holds an `IMaaKeyRegistry` immutable reference and is the only on-chain consumer.
- **`SessionRegistry`** holds an immutable `IAkCollateralVerifier` reference and calls the separately deployed verifier.
- **No relationship to `KeyResolver`.** The MAA RSA pubkey is consumed inline by the RS256 verifier; it is not registered as a `PublicIdentity` and does not appear in `KeyResolver`. The two registries serve disjoint domains.
- **No relationship to `BaseImageRegistry` / `WorkloadRegistry`.** Their owner-signed operations use the deployment's `SignatureVerifier` against `KeyResolver`-derived fingerprints; the MAA path is orthogonal.
