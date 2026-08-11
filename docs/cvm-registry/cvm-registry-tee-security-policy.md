# TeeSecurityPolicyVerifier

**File**: `src/TeeSecurityPolicyVerifier.sol`
**Interface**: `src/interfaces/ITeeSecurityPolicyVerifier.sol`
**Pattern**: immutable standalone verifier

## Purpose

`TeeSecurityPolicyVerifier` evaluates ordinary metadata and reserved security
policy after `TeeVerifier` authenticates an Intel TDX or AMD SEV-SNP report.
Keeping this work in a separate deployed contract keeps `SessionRegistry`
below the EIP-170 deployed-code size limit without mixing Intel TDX policy into
`AmdSnpSecurityPolicyRegistry`.

The constructor stores one immutable `IAmdSnpSecurityPolicyRegistry` reference.
The Intel TDX path does not call that registry. The AMD SEV-SNP path calls
`getActivePolicy` for the verified exact CPUID.

## Public interface

`amdSnpSecurityPolicyRegistry()` returns the exact registry used for AMD
SEV-SNP defaults. This function is part of `ITeeSecurityPolicyVerifier` so
off-chain clients can traverse the same dependency graph as `SessionRegistry`.

`verifyTeePolicy(inputs, profileAttributes, variantAttributes, requirements)`
first evaluates ordinary metadata. It then evaluates only the reserved keys
for `inputs.teeType`.

For Intel TDX, it checks the verified debug state and Intel DCAP TCB status
against both the effective base-image policy and workload requirements.

For AMD SEV-SNP, it checks the verified debug state, `POLICY.MIGRATE_MA`, TCB,
`PLATFORM_INFO`, and mitigation vectors. Missing packed base-image and workload
values resolve independently through the active exact-CPUID
`AmdSnpSecurityPolicyRegistry` record.

## Attribute rules

- A measurement-variant value replaces a platform-profile value with the same
  key.
- Boolean reserved values are compared directly with the verified state.
- Intel TDX TCB masks default to `ok` only.
- A reserved workload requirement must contain a value. An empty allowed set
  reverts `EmptyTeeAttributeRequirement(key)`.
- Packed reserved requirements must contain exactly one value.
- A reserved key for the other TEE type is not evaluated. One workload may
  contain policy for both supported TEE types.

## Deployment

`script/DeployTeeSecurityPolicyVerifier.s.sol` deploys the immutable verifier
after `AmdSnpSecurityPolicyRegistry` and before `SessionRegistry`. The
deployment JSON key is `TeeSecurityPolicyVerifier`.

## Errors

| Error | Condition |
|---|---|
| `SnpMitigationPolicyRequiresReportVersion(actualVersion, requiredVersion)` | A nonzero mitigation-vector mask is active, but the report version is not 5. |
| `SnpLaunchMitigationVectorMissing(requiredMask, actual)` | The signed `LAUNCH_MIT_VECTOR` is missing a required bit. |
| `SnpCurrentMitigationVectorMissing(requiredMask, actual)` | The signed `CURRENT_MIT_VECTOR` is missing a required bit. |
| `TeeAttributeBaseImageMismatch(key, declaredValue, verifiedValue)` | An effective base-image declaration does not accept the verified TEE state. |
| `TeeAttributeValueNotAllowed(key, actualValue)` | A workload requirement does not accept the verified TEE state. |
| `TeeAttributePolicyConflict(key, baseValue, workloadValue)` | Combined `PLATFORM_INFO` masks require a bit to be both set and clear. |
| `EmptyTeeAttributeRequirement(key)` | A reserved requirement has no allowed value. |
| `InvalidPackedTeeAttributeRequirementLength(key, actualLength)` | A packed reserved requirement does not contain exactly one value. |
| `AttributeNotFound(key)` | An ordinary requirement has no effective profile or variant value. |
| `AttributeValueNotAllowed(key, actualValue)` | An ordinary effective value is not allowed. |
