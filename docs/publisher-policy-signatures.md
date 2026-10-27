# Publisher policy signatures

## What changes

`registerBaseImageV2` and `addPlatformVariantsV2` add a `bytes[][] variantSignatures`
argument. Each `variantSignatures[i][j]` authenticates the full
`platformProfiles[i]` and `measurementVariants[i][j]` under the base image ID.
The matrix must have exactly the same dimensions as `measurementVariants`.

`registerWorkloadV2` adds a `bytes workloadSignature` argument. It authenticates
the workload ID and full `WorkloadSpec`.

Both signatures must verify under the `ownerIdentity` used to authorize the
publication. A workload publisher and a base image publisher can be different
entities. The workload's signed `baseImageMode`, `baseImageIds`, and `requirements`
control which base images and attributes it accepts.

The existing `ownerSignature` still authorizes the operation. It covers the new
inner signatures along with all existing publication arguments. `opExpiresAt`
applies to that authorization only. Inner signatures have no publication expiry,
chain ID, or registry address, so clients can verify the same data obtained from
an untrusted chain endpoint, an indexer, or an off-chain file.

## Exact signature inputs

All tuples use Solidity `abi.encode`, **not** `abi.encodePacked` and not JSON.
Preserve array order. The signature verifier receives the raw SHA-256 digest;
do not add an Ethereum personal-message prefix.

The existing structs and field order are defined in `src/types/Common.sol`:

```solidity
PlatformProfile = (
    string name,
    PcrBankSelection pcrBankSelection,
    PcrPolicyBlock invariantPcrPolicy,
    Attribute[] attributes
)
MeasurementVariant = (
    string name,
    PcrPolicyBlock variantPcrPolicy,
    Attribute[] attributes
)
WorkloadSpec = (
    string name,
    string version,
    uint64 sessionTtl,
    AccessMode baseImageMode,
    bytes32[] baseImageIds,
    AttributeRequirement[] requirements,
    PcrPolicyBlock workloadPcrPolicy
)
```

Inner digests:

```solidity
sha256(abi.encode(
    keccak256("CVM_BASEIMAGE_VARIANT_SIGNATURE_V1"),
    baseImageId,
    platformProfiles[i],
    measurementVariants[i][j]
))

sha256(abi.encode(
    keccak256("CVM_WORKLOAD_POLICY_SIGNATURE_V1"),
    workloadId,
    spec
))
```

Outer `ownerSignature` digests, in exact field order:

```solidity
// registerBaseImageV2
sha256(abi.encode(
    keccak256("CVM_MSG_BASEIMAGE_REGISTER_V2"),
    block.chainid, address(registry), opExpiresAt,
    spec, platformProfiles, measurementVariants, variantSignatures
))

// addPlatformVariantsV2
sha256(abi.encode(
    keccak256("CVM_MSG_BASEIMAGE_UPDATE_V2"),
    block.chainid, address(registry), opExpiresAt,
    baseImageId, platformProfiles, measurementVariants, variantSignatures
))

// registerWorkloadV2
sha256(abi.encode(
    keccak256("CVM_MSG_WORKLOAD_REGISTER_V2"),
    block.chainid, address(registry), opExpiresAt,
    spec, workloadSignature
))
```

`block.chainid` is `uint256`, `address(registry)` is the proxy address, and
`opExpiresAt` is `uint64`. `BaseImageSpec` remains `(string name, string version,
string uri)`.

## Reading and verifying

`BaseImageRegistry.getSignedVariant(baseImageId, platformProfileId, variantId)`
returns:

```solidity
struct SignedBaseImageVariant {
    BaseImageSpec baseImage;
    bytes32 ownerFingerprint;
    PublicIdentity ownerIdentity;
    PlatformProfile platformProfile;
    MeasurementVariant measurementVariant;
    bytes variantSignature;
}
```

`WorkloadRegistry.getSignedWorkload(workloadId)` returns:

```solidity
struct SignedWorkload {
    WorkloadSpec spec;
    bytes32 ownerFingerprint;
    PublicIdentity ownerIdentity;
    bytes workloadSignature;
}
```

Each result contains the actual public key. Clients do not need to trust a
registry lookup that claims a key belongs to a fingerprint. They recompute it:

```solidity
fingerprint = keccak256(abi.encode(
    keccak256("KEY_RESOLVER_V1"), ownerIdentity.typeId, ownerIdentity.key
));
workloadId = keccak256(abi.encode(
    keccak256("CVM_WORKLOAD_V1"), fingerprint, spec.name, spec.version
));
baseImageId = keccak256(abi.encode(
    keccak256("CVM_BASEIMAGE_V1"), fingerprint, baseImage.name, baseImage.version
));
platformProfileId = keccak256(abi.encode(
    keccak256("CVM_PLATFORM_PROFILE_V1"), baseImageId, platformProfile.name
));
variantId = keccak256(abi.encode(
    keccak256("CVM_PLATFORM_VARIANT_V1"), platformProfileId, measurementVariant.name
));
```

For a known workload ID, the client must:

1. Recompute the workload publisher fingerprint and workload ID. Require an exact
   match to the requested workload ID and the returned fingerprint.
2. Verify `workloadSignature` locally with the returned public key and the full
   `WorkloadSpec`. Use the supported algorithm identified by `PublicIdentity.typeId`.
3. For the selected base image, independently recompute its publisher fingerprint,
   image ID, profile ID, and variant ID. Require all requested IDs to match.
4. Verify `variantSignature` locally over the full profile and selected variant.
5. Enforce the signed workload's base-image access rule and attribute requirements.
   Evaluate all required PCR policy blocks against the authenticated attestation.

Do not ask an untrusted registry's signature-verification method to decide
whether its own result is valid. The verifier must be part of the trusted client.
A fingerprint is a hash: it cannot be reversed to recover the key. The response
supplies the key, and recomputing the fingerprint binds it to the requested ID.

The inner variant signature does not authenticate `BaseImageSpec.uri`. The URI
is metadata only; do not use it as a trusted policy input. Image name and version
are bound through the recomputed base image ID.

## Compatibility and limits

- V1 publication functions, signature digests, getters, IDs, and storage fields
  remain unchanged. The existing `SessionRegistry` works without an upgrade.
- V2 signatures are mandatory on V2 calls. Empty, missing, altered, and
  wrong-publisher signatures are rejected.
- The new getters reject V1 records without an inner signature using
  `VariantSignatureUnavailable` or `WorkloadSignatureUnavailable`. Clients that
  require independent policy verification must reject this absence explicitly.
- Appending a V2 variant to a V1 image is supported. That authenticates the new
  variant and its full parent profile; it does not add signatures to old variants.
- Existing profile contents and variant IDs cannot be overwritten. Initial
  publication and later additions use the same inner signature format.
- Signatures establish publisher approval and internal consistency. They do not
  prove freshness, non-revocation, completeness of the variant list, or canonical
  registration. A publisher can sign different policies for the same name and
  version. A trusted source of current state is still needed for those claims.
- Signed getters can return data for revoked records. Revocation does not erase
  the publisher's historical signature.

`BaseImageRegistry` consumes reserved storage slots 4 and 5 and retains a 44-slot
storage gap. `WorkloadRegistry` consumes slots 3 and 4 and retains a 45-slot gap.
Existing mapping and nested struct layouts are unchanged.

## Tests and fork rehearsal

```sh
forge test

HOODI_FORK_BLOCK_NUMBER=$(cast block-number --rpc-url http://139.99.100.76:8545) \
HOODI_FORK_RPC=http://139.99.100.76:8545 \
HOODI_FORK_SESSION_REGISTRY=0x7575BceC155b272077C87aD3Ae5Ef54Cf9DC6601 \
forge test --match-contract PublisherSignaturesForkTest --threads 1 --rpc-timeout 600 --no-rpc-rate-limit -vv
```

The opt-in fork suite upgrades the inherited proxies in a local test snapshot.
It checks existing records and slots before running the real-signature tests.
It sends no transactions to the remote fork.

`script/PublisherSignaturesHoodiFork.s.sol` is a separate broadcast rehearsal. It
requires chain ID 31337 and an explicitly supplied `HOODI_FORK_SESSION_REGISTRY`.
Verify the configured RPC is the controlled fork, resolve its registry admin,
and unlock that admin with Anvil impersonation before using `--unlocked --broadcast`.
The script upgrades the two registries, publishes three variants, appends three,
and publishes a workload under a separate public test key. It removes the test
publishers' whitelist entries afterward. Always stop impersonating the admin
when the rehearsal ends, including after failure.

After broadcasting, run the script with `--sig 'verifyPublished()'` without
`--broadcast` to check the mined records. Publication uses fixed test identities;
a repeat publication must not evade duplicate checks by inventing a version.
This script tests contract behavior, not hardware attestation or Portal integration.
