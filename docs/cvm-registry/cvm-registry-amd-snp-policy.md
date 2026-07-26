# AmdSnpSecurityPolicyRegistry

`AmdSnpSecurityPolicyRegistry` is a UUPS registry. It stores the mandatory AMD
SEV-SNP security floor for each exact processor family, model, and stepping.
`SessionRegistry` calls it after `TeeVerifier` authenticates and parses a
report.

The CPUID key is `(family << 16) | (model << 8) | stepping`. This version
supports AMD family `0x19`, model `0x00` through `0x1f`. Turin is not
supported.

Each active record stores:

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

The owner updates a CPUID-sorted array through `updatePolicies`. Revisions can
only move forward. `sourceDigest` must be nonzero. A missing or inactive
policy rejects the session. The global values are a floor. Base-image and
workload policy may make the checks stricter but cannot weaken the global
values.

The checked `script/UpdateAmdSnpSecurityPolicies.s.sol` reads a JSON
`policies` array and stores the Keccak-256 hash of the exact file as
`sourceDigest`.
