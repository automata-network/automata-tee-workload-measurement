# DCAP V2 integration

The new TeeVerifier uses `DCAP_V2_ATTESTATION_ADDR` for raw TDX quotes.
`DCAP_ATTESTATION_ADDR` still belongs to the V1 ZK adapter. They are separate
contracts; the old FeeV2 deployment cannot stand in for compact V2.

Both ZK adapters return the existing internal `IntelTdxDcapCompactOutputV1`.
The registry routes exact V1 and V2 program IDs to their own adapter. Session
submission types and attribute/security-policy checks remain unchanged.

`DeployIntelTdxDcapV2Adapter.s.sol` deploys the new adapter only.
`RegisterIntelTdxDcapV2ProgramIdentifier.s.sol` adds its accepted minimal SP1
program to an explicitly addressed existing registry. It checks program mode,
pause state, the actual proof selector's verifier, and preservation of the V1
route. It refuses to overwrite another adapter. DCAP owner registration and
real-proof verification are prerequisites; these scripts do neither.

Use the actual four-byte selector from the verified proof, right-padded to
32 bytes for `DCAP_V2_PROOF_SELECTOR`. The script does not infer it from an SDK
version. A verifier with code is a configuration check, not proof acceptance.
Read back the resulting configuration from the chain after broadcast.

Before switching SessionRegistry's TeeVerifier dependency, simulate the upgrade
and check V1's external DCAP acceptance/verifier settings, V2 real proofs, old
image registration/renewal/recovery, and preservation of existing session records.
No public upgrade or deployment is part of the codec/adapter unit tests.
