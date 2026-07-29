# maa-key-registrar

Off-chain admin tool for the on-chain [`MaaKeyRegistry`](../../src/MaaKeyRegistry.sol). Fetches the Microsoft Azure Attestation JWKS (`<endpoint>/certs`), derives the four `upsertMaaSigningKey` arguments per key, diffs against on-chain state, and broadcasts upsert / revoke transactions.

Spec: [`cvm-registry-maa-key.md`](../../docs/cvm-registry/cvm-registry-maa-key.md).

## Build

```sh
cargo build --release -p maa-key-registrar
# binary at ./target/release/maa-key-registrar
```

## Subcommands

### `derive` — offline argument derivation

Fetch JWKS, print the four args (`kidHash`, `pkcs1Pubkey`, `issuerHash`, `notAfter`) for every kid that survives the cert filter. No on-chain calls. Use this to sanity-check arg derivation before submitting.

```sh
# Default: shared eastus pool, iss = endpoint URL, filter = self-signed RSA ≥ 2048
maa-key-registrar derive

# Override endpoint
maa-key-registrar derive --endpoint https://sharedwus.wus.attest.azure.net

# Override the iss string (custom MAA tenants emitting a non-endpoint iss)
maa-key-registrar derive --iss "https://my-tenant.eus.attest.azure.net"

# Tenant-mode MAA — accept chained Microsoft-PKI cert too
maa-key-registrar derive --include any

# Forensics: include every JWKS entry, including RSA-1024 legacy
maa-key-registrar derive --include all

# JSON output (machine-readable)
maa-key-registrar derive --json
```

#### Cert filter

`--include` controls which JWKS entries become upsert candidates:

| Value | Keeps | Use for |
|---|---|---|
| `self-signed` (default) | self-signed leaves (`subject == issuer`) with RSA ≥ 2048 | MAA shared pools (`shared<region>.<region>.attest.azure.net`) |
| `any` | every leaf with RSA ≥ 2048 | tenant-mode MAA (custom endpoints emitting JWTs signed by a Microsoft-chained cert) |
| `all` | everything in JWKS, no filter | forensics only |

Why the default isn't `any`: the JWKS at a shared-pool endpoint typically contains both (a) the self-signed `CN=<endpoint>` certs that are actually used to sign attestation JWTs and (b) the Microsoft enterprise-PKI chained cert used by tenant-mode MAA instances. Registering the chained cert on a deployment that only talks to shared pools grants signing trust to a key the shared pool will never emit a JWT under — a strict net loss. The RSA-2048 minimum drops MAA's legacy RSA-1024 keys that occasionally still appear in JWKS.

### `status` — diff JWKS vs on-chain registry

Fetch JWKS, read every kid's complete state from `MaaKeyRegistry`, and classify
each as `current` / `missing` / `drifted` / `expiring <30d` / `revoked`.

```sh
maa-key-registrar status \
  --rpc http://139.99.100.76:8545 \
  --registry 0x43AE47776f1405A844a73074eFC0f77d7b47599E
```

`drifted` means the kid is registered but at least one of `pkcs1Pubkey` /
`issuerHash` / `notAfter` disagrees with current JWKS — typically a sign that
Microsoft rotated the cert and your watcher missed it. Run `sync` to fix.
`revoked` means the `kidHash` was permanently revoked and cannot be upserted
again.

### `sync` — upsert anything missing / drifted / expiring

Owner-only. Reads JWKS + on-chain state, plans the necessary upserts, and
broadcasts them after a y/N prompt. Refuses to upsert eligible kids with
`notAfter < now + 24h` (signal of stale JWKS / clock drift). Revoked kids are
reported and skipped. Pass `--force` to re-upsert kids that are already
current and not revoked. `--force` never bypasses revocation.

```sh
maa-key-registrar sync \
  --rpc <RPC_URL> \
  --registry 0x... \
  --owner-key /path/to/owner.key
  # or:  --owner-key 0xac09...80
  # or:  $ATAKIT_MAA_OWNER_KEY=0xac09...80 maa-key-registrar sync ...

# Print the cast send commands instead of broadcasting
maa-key-registrar sync ... --dry-run

# Skip the y/N prompt
maa-key-registrar sync ... -y
```

`--dry-run` is the safe path on a production multisig: print the commands, hand them to whoever drives the safe, no hot key required.

Revocation is permanent for each `kidHash`. The `sync` command reads
`getMaaSigningKey`, reports revoked kids separately, and skips them even when
`--force` is used. The contract also rejects every later
`upsertMaaSigningKey` call for a revoked `kidHash`.

### `revoke` — revoke one kid

```sh
maa-key-registrar revoke \
  --kid 'rFl9xM+g7TvX63y0iseZtIn20MD5SYAnGblKFasau8I=' \
  --rpc <RPC_URL> \
  --registry 0x... \
  --owner-key /path/to/owner.key

# Print cast command only
maa-key-registrar revoke ... --dry-run
```

The kid string is what appears in the JWT header — NOT the keccak256 hash. The tool hashes it for you.

## Owner key sourcing

`--owner-key` accepts, in order of preference:

1. A path to a file containing the hex key (`0x…` or bare hex on a single line).
2. The literal hex value (handy for testing; leaks to shell history).
3. The value of `$ATAKIT_MAA_OWNER_KEY` (used implicitly when `--owner-key` is omitted).

In production the owner is a multisig; use `--dry-run` to emit `cast send` lines and broadcast them via the multisig executor. The CLI does not natively support multisig submission.

## What the tool does NOT do

- **No JWKS rotation watcher.** This is a one-shot CLI. Run it from cron or a systemd timer if you want continuous monitoring (see the spec's "Key Rotation" section for cadence guidance).
- **No multi-region orchestration.** Run once per MAA endpoint you support.
- **No JWT issuer probe.** `--iss` defaults to the endpoint URL, which is correct for MAA shared pools but not enforced. For custom tenants, attest once, read the JWT `iss` claim, and pass it via `--iss`.

## Implementation notes

- `pkcs1Pubkey` is parsed from `x5c[0]` (the leaf cert) rather than the JWK `n`/`e` fields. The X.509 `SubjectPublicKeyInfo` BIT STRING contents for `rsaEncryption` (OID 1.2.840.113549.1.1.1) are the DER PKCS#1 `RSAPublicKey` directly, so no further re-encoding is needed.
- `notAfter` is the leaf cert's validity end, in Unix seconds.
- `kidHash` is `keccak256(bytes(kid))`. The on-chain verifier uses the same hash from the JWT header.
- `issuerHash` is `keccak256(bytes(iss))`, where `iss` must match the JWT `iss` claim byte-for-byte.

Update both the inline `alloy::sol!` block in [`src/chain.rs`](src/chain.rs) and the on-chain interface ([`IMaaKeyRegistry.sol`](../../src/interfaces/registries/IMaaKeyRegistry.sol)) together if the contract ABI changes.
