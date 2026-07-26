# AmdSnpSecurityPolicyRegistry

**File**: `src/AmdSnpSecurityPolicyRegistry.sol`
**Interface**: `src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol`
**Pattern**: UUPS upgradeable proxy
**Owner model**: OpenZeppelin `OwnableUpgradeable`

## Purpose

`AmdSnpSecurityPolicyRegistry` stores the mandatory AMD SEV-SNP security floor
for each exact processor family, model, and stepping. `SessionRegistry` calls
it after `TeeVerifier` verifies and extracts the signed report.

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
}
```

`minimumTcb` contains four 64-bit lanes. From high to low, they are current,
reported, committed, and launch TCB. Each lane stores bootloader, TEE, SNP,
and microcode as four 8-bit components. The upper 32 bits are zero.

`platformInfoPolicy` stores the required-set mask in its low 64 bits and the
required-clear mask in its next 64 bits. The masks cannot overlap. This
version supports `PLATFORM_INFO` bits 0 through 5.

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
- A deactivation requires both packed policy values to be zero.
- A missing or inactive policy cannot authorize a session.
- Only the owner may update policies or authorize an implementation upgrade.

An inactive update leaves the last stored `minimumTcb` and
`platformInfoPolicy` in the record for audit history. The update call must
still supply zero for both fields. A same-revision, identical update is a
no-op; it does not replace the stored `sourceDigest` or emit an event.

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
2. checks debug and `POLICY.MIGRATE_MA`;
3. checks the report against the component-wise maximum of the global and
   base-image TCB minimums;
4. checks the report against the component-wise maximum of the global and
   workload TCB minimums;
5. merges global, base-image, and workload `PLATFORM_INFO` required-set and
   required-clear masks;
6. rejects a mask conflict or a report that does not satisfy the merged masks.

The complete packed formats are defined in the canonical
AMD SEV-SNP security policy specification in the atakit suite.

## Event

`AmdSnpSecurityPolicyUpdated(cpuid, revision, active, minimumTcb,
platformInfoPolicy, sourceDigest)` records each applied change. `cpuid` is
indexed. Same-revision no-op updates do not emit it.

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
| `PolicyRevisionConflict(cpuid, revision)` | A same-revision update changes active state or active policy content. |
| `InvalidInactivePolicy(cpuid, minimumTcb, platformInfoPolicy)` | A deactivation supplies a nonzero packed policy. |
| `InvalidAmdSnpTcbValue(actual)` | An active update supplies a TCB value with a nonzero unsupported or reserved byte. |
| `InvalidAmdSnpPlatformInfoPolicy(actual)` | An active update supplies unsupported, overlapping, or nonzero reserved `PLATFORM_INFO` policy bits. |
| `TeeAttributeBaseImageMismatch(key, declaredValue, verifiedValue)` | An effective base-image declaration does not accept the verified TEE state. |
| `TeeAttributeValueNotAllowed(key, actualValue)` | A workload requirement does not accept the verified TEE state. |
| `TeeAttributePolicyConflict(key, baseValue, workloadValue)` | Combined `PLATFORM_INFO` masks require a bit to be both set and clear. |
| `AttributeNotFound(key)` | An ordinary workload attribute has no effective profile or variant value. |
| `AttributeValueNotAllowed(key, actualValue)` | An ordinary effective attribute value is not allowed. |
