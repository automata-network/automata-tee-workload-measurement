# AmdSnpSecurityPolicyRegistry

**File**: `src/AmdSnpSecurityPolicyRegistry.sol`
**Interface**: `src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol`
**Pattern**: UUPS upgradeable proxy
**Owner model**: OpenZeppelin `OwnableUpgradeable`

## Purpose

`AmdSnpSecurityPolicyRegistry` stores AMD SEV-SNP policy defaults for each
exact processor family, model, and stepping. `SessionRegistry` calls it after
`TeeVerifier` verifies and extracts the signed report. The record supplies a
missing base-image or workload TCB or `PLATFORM_INFO` value. Those values are
not independent mandatory floors. The record also carries mandatory
version-5 mitigation-vector masks.

The registry also evaluates reserved TEE attributes and ordinary metadata
requirements. This keeps `SessionRegistry` below the EIP-170 deployed-code
size limit.

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
| `verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements)` | Evaluates ordinary metadata and the reserved policy for `inputs.teeType`. |

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

`script/UpdateAmdSnpSecurityPolicies.s.sol` reads the proxy address from
`AMD_SNP_SECURITY_POLICY_REGISTRY` and a JSON `policies` array from
`AMD_SNP_SECURITY_POLICY_FILE`. It stores the Keccak-256 hash of the exact file
text as `sourceDigest`.

## Session evaluation

`verifyTeePolicy` first applies ordinary attribute requirements. It then
evaluates only the reserved attributes for the verified TEE type.

For Intel TDX, it checks debug and Intel DCAP TCB status.

For AMD SEV-SNP, it:

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

The complete packed formats are defined in the canonical
AMD SEV-SNP security policy specification in the atakit suite.

## Event

`AmdSnpSecurityPolicyUpdated(cpuid, revision, active, minimumTcb,
platformInfoPolicy, requiredLaunchMitigationVector,
requiredCurrentMitigationVector, sourceDigest)` records each applied change.
`cpuid` is indexed. Same-revision no-op updates do not emit it.

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
| `SnpMitigationPolicyRequiresReportVersion(actualVersion, requiredVersion)` | A nonzero mitigation-vector mask is active, but the report version is not 5. |
| `SnpLaunchMitigationVectorMissing(requiredMask, actual)` | The signed `LAUNCH_MIT_VECTOR` is missing a required bit. |
| `SnpCurrentMitigationVectorMissing(requiredMask, actual)` | The signed `CURRENT_MIT_VECTOR` is missing a required bit. |
| `TeeAttributeBaseImageMismatch(key, declaredValue, verifiedValue)` | An effective base-image declaration does not accept the verified TEE state. |
| `TeeAttributeValueNotAllowed(key, actualValue)` | A workload requirement does not accept the verified TEE state. |
| `TeeAttributePolicyConflict(key, baseValue, workloadValue)` | Combined `PLATFORM_INFO` masks require a bit to be both set and clear. |
| `AttributeNotFound(key)` | An ordinary workload attribute has no effective profile or variant value. |
| `AttributeValueNotAllowed(key, actualValue)` | An ordinary effective attribute value is not allowed. |
