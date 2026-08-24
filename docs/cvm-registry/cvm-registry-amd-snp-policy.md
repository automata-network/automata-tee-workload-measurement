# AmdSnpSecurityPolicyRegistry

**File**: `src/AmdSnpSecurityPolicyRegistry.sol`
**Interface**: `src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol`
**Pattern**: UUPS upgradeable proxy
**Owner model**: OpenZeppelin `OwnableUpgradeable`

## Purpose

`AmdSnpSecurityPolicyRegistry` stores AMD SEV-SNP policy defaults for each
exact processor family, model, and stepping. `TeeSecurityPolicyVerifier` reads
the active record when it evaluates an AMD SEV-SNP report. The record supplies
a missing base-image or workload TCB or `PLATFORM_INFO` value. Those values are
not independent mandatory floors. The record also carries mandatory version-5
mitigation-vector masks.

## Storage

```solidity
mapping(uint24 => AmdSnpSecurityPolicy) private _policies;
uint256[49] private __gap;
```

The CPUID key is `(family << 16) | (model << 8) | stepping`. This version
supports AMD family `0x19`, model `0x00` through `0x1f`. Turin is not
supported.

```solidity
struct AmdSnpSecurityPolicy {
    bytes32 minimumTcb;
    bytes32 platformInfoPolicy;
    bytes32 sourceDigest;
    uint64 revision;
    bool active;
    uint64 requiredLaunchMitigationVector;
    uint64 requiredCurrentMitigationVector;
}
```

`minimumTcb` contains four 64-bit lanes. From high to low, they are current,
reported, committed, and launch TCB. Each lane stores bootloader, TEE, SNP,
and microcode as four 8-bit components. The upper 32 bits are zero.

`platformInfoPolicy` stores the required-set mask in its low 64 bits and the
required-clear mask in its next 64 bits. The masks cannot overlap. This
version supports `PLATFORM_INFO` bits 0 through 5.

The mitigation-vector fields are required bit masks for the signed version-5
`LAUNCH_MIT_VECTOR` and `CURRENT_MIT_VECTOR` fields. Extra report bits are
allowed. A nonzero mask requires report version 5. Base-image and workload
policy cannot replace these masks. Existing stored policies read both masks
as zero after the implementation upgrade.

## Public interface

| Function | Behavior |
|---|---|
| `initialize(initialOwner)` | Initializes a new proxy once and sets its owner. |
| `updatePolicies(updates, sourceDigest)` | Applies an owner-authorized, CPUID-sorted update batch. |
| `getPolicy(cpuid)` | Returns an existing active or inactive policy. |
| `getActivePolicy(cpuid)` | Returns an existing active policy. |

## Updates

`updatePolicies` accepts a non-empty array sorted by increasing CPUID and a
nonzero `sourceDigest`.

- A new policy needs a nonzero revision.
- A later change needs a higher revision.
- Repeating the same revision is allowed only when the policy is identical.
- A deactivation requires both packed policy values and both mitigation-vector
  masks to be zero.
- A missing or inactive policy cannot authorize a session.
- Only the owner may update policies or authorize an implementation upgrade.

An inactive update leaves the last stored `minimumTcb` and
`platformInfoPolicy` and both masks in the record for audit history. The
update call must still supply zero for all four policy fields. A same-revision,
identical update is a no-op; it does not replace the stored `sourceDigest` or
emit an event.

`script/DeployAmdSnpSecurityPolicyRegistry.s.sol` deploys and initializes the
implementation and proxy. `script/DeployProd.s.sol` includes the same step in
a fresh complete deployment.

Every fresh `SessionRegistry` deployment also requires
`AWS_NITRO_ROOT_CERT_HASH`. The value is the Keccak-256 hash of the exact
trusted AWS NitroTPM root certificate DER. The deployment records that trust
before it reports success.

`script/UpdateAmdSnpSecurityPolicies.s.sol` reads the proxy address from
`AMD_SNP_SECURITY_POLICY_REGISTRY` and a JSON `policies` array from
`AMD_SNP_SECURITY_POLICY_FILE`. It stores the Keccak-256 hash of the exact file
text as `sourceDigest`.

`policies/amd-snp-milan-b1.json` is the reviewed fresh-deployment policy for
CPUID `0x190101`. Its launch and current mitigation-vector masks are `0x16`,
which requires bits 1, 2, and 4. An attestation report with vectors `0x0f`
fails this policy because it does not contain bit 4.

`policies/amd-snp-milan-b1-cross-cloud.json` is the reviewed cross-cloud
policy for CPUID `0x190101`. It uses the component-wise Azure, GCP, and AWS
minimum TCB, platform-information policy `0x20`, and zero launch and current
mitigation-vector masks. The zero masks are required for the tested Azure
version-3 report, which does not contain signed mitigation-vector fields. Use
this file only when the release explicitly intends to support that Azure
report together with the tested GCP and AWS version-5 reports.

The mask follows AMD-SB-3020 bit 1, AMD-SB-3016 bit 2, and AMD-SB-3030 and
AMD-SB-3034 bit 4 for Milan. Those bulletins are available from AMD's Product
Security index at `https://www.amd.com/en/resources/product-security.html`.

## Use by TeeSecurityPolicyVerifier

`TeeSecurityPolicyVerifier.verifyTeePolicy` calls `getActivePolicy` only for
AMD SEV-SNP evidence. It then:

1. requires an active record for the verified exact CPUID;
2. requires report version 5 when either mitigation-vector mask is nonzero;
3. requires each signed mitigation vector to contain every required bit;
4. checks debug and `POLICY.MIGRATE_MA`;
5. resolves the base-image TCB minimum from the measurement variant, then the
   platform profile, then the registry default;
6. resolves the workload TCB minimum from an explicit requirement or the
   registry default;
7. checks the report against the component-wise maximum of those two resolved
   minimums;
8. resolves base-image and workload `PLATFORM_INFO` policies with the same
   missing-value rules;
9. combines the two resolved required-set masks and required-clear masks;
10. rejects a mask conflict or a report that does not satisfy the combined
   masks.

One explicit side cannot relax a registry default because the missing other
side still resolves to that default. Matching explicit base-image and workload
values can relax it. Verification without a workload applies only the resolved
base-image policy.

### The registry value is a default, not a floor

This is the security property the packed reserved attributes actually provide,
stated plainly so integrators do not over-read it.

`minimumTcb` and `platformInfoPolicy` are **defaults that fill in a missing
side**, not floors that bound either side. `WorkloadRegistry` validates the
*shape* of a `tcb.minimum` requirement, never its magnitude, and `bytes32(0)`
is a well-formed TCB. A base image and a workload that both explicitly declare
a weaker value than the registry record will be admitted at that weaker value.

What the registry does guarantee is that relaxing takes **two independent
parties**: the base-image owner and the workload owner must each opt in, since
whichever side stays silent re-imposes the registry value. Treat the record as
a coordination point and a safe default for silent operators, not as a
platform-wide minimum that cannot be undercut.

The mitigation-vector masks are different, and are the exception: base-image
and workload policy cannot replace them, so they are true mandatory
requirements for the CPUID.

Two consequences worth carrying into integration:

- A relying party that needs a specific TCB floor must assert it itself, from
  the session's `baseImageId`, `measurementVariantId`, and `workloadId` — the
  registry default alone does not establish it.
- Raising a registry record does not retroactively tighten a base image or
  workload that already declares its own explicit value.

The complete packed formats are defined in the canonical
AMD SEV-SNP security policy specification in the atakit suite.

## Event

`AmdSnpSecurityPolicyUpdated(cpuid, revision, active, minimumTcb,
platformInfoPolicy, requiredLaunchMitigationVector,
requiredCurrentMitigationVector, sourceDigest)` records each applied change.
`cpuid` is indexed. Same-revision no-op updates do not emit it.

The policy fields report **what the update applied**, not what storage holds
afterwards. The two differ only on a deactivation, which must supply zeros
while the record keeps its previous values for audit history: the event carries
the zeros. An indexer can therefore rebuild applied policy from the log alone,
and should read `active` to decide whether a CPUID can authorize a session.
Read `getPolicy` for the retained historical values.

Each update supplies `expectedRevision`. A new policy uses zero. An existing
policy update succeeds only when `expectedRevision` equals the stored revision.
This stops an older reviewed update from overwriting a newer update. Retrying
an identical update at the already-stored revision remains a no-op.

## Errors

| Error | Condition |
|---|---|
| `EmptyPolicyUpdate()` | The update array is empty. |
| `InvalidSourceDigest()` | `sourceDigest` is zero. |
| `PolicyUpdatesNotSorted(previousCpuid, actualCpuid)` | CPUID entries are not strictly increasing. |
| `UnsupportedCpuid(cpuid)` | CPUID is outside AMD family `0x19`, model `0x00` through `0x1f`. |
| `PolicyNotFound(cpuid)` | The requested policy does not exist, or a deactivation targets no existing record. |
| `PolicyNotActive(cpuid)` | The requested or session-selected policy is inactive. |
| `InvalidPolicyRevision(cpuid, actual, expectedMinimum)` | A new revision is zero or a later revision moves backward. |
| `PolicyRevisionMismatch(cpuid, actual, expected)` | The policy changed after this update was prepared. |
| `PolicyRevisionConflict(cpuid, revision)` | A same-revision update changes active state or active policy content. |
| `InvalidInactivePolicy(cpuid, minimumTcb, platformInfoPolicy, requiredLaunchMitigationVector, requiredCurrentMitigationVector)` | A deactivation supplies a nonzero policy field. |
| `InvalidAmdSnpTcbValue(actual)` | An active update supplies a TCB value with a nonzero unsupported or reserved byte. |
| `InvalidAmdSnpPlatformInfoPolicy(actual)` | An active update supplies unsupported, overlapping, or nonzero reserved `PLATFORM_INFO` policy bits. |
