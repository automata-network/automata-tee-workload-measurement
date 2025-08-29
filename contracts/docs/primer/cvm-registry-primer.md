# CVM Registry Primer

Status: Draft  
Scope: Overview of `CVMRegistry` contract, lifecycle, trust assumptions, and identified issues (including `WorkloadVerifier` interactions).

---

## 1. Purpose

`CVMRegistry` maps a Confidential VM (CVM) workload identity (a TPM / workload–generated public key) to:
- Its attestation configuration (TEE type, cloud provider)
- The latest trusted measurement hash
- Time-to-live (TTL) windows for TEE and TPM collateral freshness
- Attestation artifacts (TEE output, TPM Attestation Key)
- Nonce state for signed maintenance actions (reattestation, TTL changes)

Once registered, the CVM’s identity key can sign authorized messages (with domain separation) enabling downstream onchain actions gated by workload integrity + liveness (via TTL).

---

## 2. Key External Dependencies

| Component | Responsibility |
|----------|----------------|
| `WorkloadVerifier` | Verifies TEE report (on-chain or via ZK) + TPM quote + PCR measurements. Produces `TEEVerifiedData`, TPM extra data, and canonical measurement. |
| `ITpmAttestation` | Verifies TPM quote, extracts PCRs, parses extra data (which embeds CVM identity hash). |
| TEE Attestation libs (DCAP / SNP / ZK) | Provide raw TEE attestation validation primitives. |

---

## 3. Core Data Structures

### `CVMConfig`
```
struct CVMConfig {
    TEEType teeType;
    CloudType cloudType;
    uint64 teeTTL;
    uint64 tpmTTL;
    uint64 teeRecentTimestamp;
    uint64 tpmRecentTimestamp;
    bytes32 measurementHash;
    bytes teeAttestationOutput;
    Pubkey cvmIdentity; // workload identity key
    Pubkey tpmAk;       // TPM Attestation Key
}
```

### Internal Mappings
- `_configs[bytes32 cvmIdentityHash] => CVMConfig`
- `_nonces[bytes32 cvmIdentityHash] => uint256` (monotonic for replay protection of signed ops)

### Identity Hash
```
keccak256(abi.encodePacked(pub.sigScheme, pub.curve, pub.hashAlgo, pub.data))
```

---

## 4. Lifecycle

### 4.1 Registration (`attestCvm`)
1. Derive `cvmIdentityHash` from `wc.cvmIdentity`.
2. If first-time:
   - Initialize cloud/TEE types and default TTLs (`DEFAULT_TEE_TTL = 30d`, `DEFAULT_TPM_TTL = 60d`).
3. Call `workloadVerifier.verifyAttestation(...)`:
   - Verifies: TEE report, TPM quote, PCRs.
   - Returns `teeAttestationOutput`, `TEEVerifiedData`, and `tpmExtraData`.
4. Extract identity hash from `tpmExtraData`; MUST match computed identity.
5. Compute canonical measurement via `workloadVerifier.getMeasurement(...)`.
6. Persist config (identity, timestamps, measurement hash, TPM AK).
7. Emit `CVMUpdated`.

No signature from the CVM identity is required for initial registration (bootstrapped solely by attestation binding).

### 4.2 Re-attestation (TPM-only) & Optional Key Rotation (`reattestCvmWithTpm`)
Use when:
- TPM collateral expired but TEE collateral still within TTL.
- Identity key rotation is desired.

Steps:
1. Validate CVM-signed request:
   - Message = prefix + chainid + contract + (nonce, sha256(tpmQuote)).
   - Signature verified against stored `cvmIdentity`.
2. Verify TPM quote (using stored `tpmAk`).
3. Check PCR measurements + extract new `extraData`.
4. Reconstruct measurement (TEE report reused).
5. If `wc.cvmIdentity` hash differs:
   - Ensure TPM extra data embeds the *new* identity hash.
   - Rotate config to new hash, copying prior attest state.
6. Else, update `measurementHash` & TPM freshness timestamp.
7. Emit `CVMUpdated`.

TEE freshness timestamp is NOT refreshed here; design enforces periodic full re-attestation at TEE TTL boundary.

### 4.3 TTL Adjustment (`setCollateralTTL`)
- Signed by current CVM identity:
  - Message = prefix + chainid + contract + (nonce, newTEEttl, newTPMttl).
- Updates `teeTTL` / `tpmTTL`.
- Emits `CVMTTLUpdated`.
- (Current implementation does not enforce bounds or require current collateral validity.)

---

## 5. Freshness Semantics

| Type | Tracked Timestamp | TTL | Validity Check |
|------|-------------------|-----|----------------|
| TEE  | `teeRecentTimestamp` | `teeTTL` | `(block.timestamp - teeRecentTimestamp) < teeTTL` |
| TPM  | `tpmRecentTimestamp` | `tpmTTL` | `(block.timestamp - tpmRecentTimestamp) < tpmTTL` |

Re-attestation (TPM path) only touches TPM timestamp (and measurement hash). Full registration flow required to refresh TEE timestamp.

---

## 6. Message Domain Separation

`CVMSignature` constructs messages:
```
abi.encodePacked(prefix, uint16(chainid), address(this), userData)
```
Distinct prefixes:
- `"CVM_WORKLOAD_REATTEST_TPM"`
- `"CVM_WORKLOAD_TTL_CONFIG"`
- `"CVM_WORKLOAD_USER_MESSAGE"` (general user payloads)
Provides:
- Contract binding
- Chain binding
- Operation-specific domain separation.

---

## 7. Measurement Handling

Canonical measurement = hash of `Measurement` struct where `WorkloadVerifier.getMeasurement`:
- Converts measured PCRs to final set
- Zeroes `tdx.rtmr3` (contains reboot-variant UUID) to stabilize measurement across restarts.

Registry stores only `bytes32 measurementHash` (digest). Consumers should treat this as workload integrity anchor.

---

## 8. Security & Trust Assumptions

| Aspect | Assumption |
|--------|------------|
| Identity Binding | TPM quote `extraData` embeds CVM identity hash; TEE report binds TPM AK (Azure: hash in reportData; GCP: certificate chain). |
| Nonce Replay Protection | Per-identity monotonically incremented `_nonces`. |
| Upgradeability | UUPS with `onlyOwner` control; immutables (`workloadVerifier`, `tpmAttestation`) fixed at deployment for an implementation slot. |
| Key Rotation | Must be proven via TPM extra data containing new identity hash while old key signs rotation request. |

---

## 9. Identified Issues / Observations

Severity legend: High / Medium / Low / Informational

1. High (RESOLVED): Measurement Normalization on Re-attestation  
   - `reattestCvmWithTpm` now calls `workloadVerifier.getMeasurement`, inheriting normalization (zeroing `tdx.rtmr3`).  
   - Prior manual construction caused false measurement hash diffs for TDX workloads after TPM-only re-attest.  
   - Fix merged: prevents spurious integrity changes; measurement hash stability confirmed.

2. High (RESOLVED): Key Rotation Copies `tpmAk`  
   - `_rotateCvmIdentity` now assigns `newConfig.tpmAk = oldConfig.tpmAk;`.  
   - Previously omission risked failed future TPM quote verifications post-rotation.  
   - Fix merged: preserves continuous attestation capability across identity rotations.

3. Medium: TTL Change Does Not Enforce Current Freshness  
   - Comment: `sig + TEE and TPM validity` but function only checks signature.  
   - Potential for extending TTL after collateral already expired.  
   - Fix: Require `checkTEEValidity` and `checkTPMValidity` true before update, or bound how far timestamps can lag.

4. Medium: Unbounded TTL Inputs  
   - Accepts zero (permanent invalidity) or excessively large values (stale acceptance risk).  
   - Fix: Enforce `minTTL <= value <= maxTTL`.

5. Medium: Silent Parameter Mismatch on Re-registration Attempt  
   - `attestCvm` ignores passed `cloudType` / `teeType` if already registered (no revert on mismatch).  
   - Could hide caller misconfiguration.  
   - Fix: If registered, require provided types match stored config.

6. Medium: Nonce Not Carried During Key Rotation (Design Choice)  
   - Rotation resets nonce to 0 for new identity; acceptable but should be explicit.  
   - Document to avoid mistaken reliance on continuity.

7. Low: `_parseIdentityFromTpmData` Missing Explicit Length Check  
   - If `tpmExtraData.length < 33`, internal `substring` reverts with generic error instead of custom `INVALID_TPM_DATA_LENGTH`.  
   - Fix: Add `require(tpmExtraData.length >= 33, "INVALID_TPM_DATA_LENGTH");`.

8. Low: No Revocation Mechanism  
   - Cannot explicitly deactivate an identity before TTL expiry.  
   - Consider an onchain `revokeCvm` requiring identity signature.

9. Low: Upgrade Risk – Immutables vs Future Impl Needs  
   - `workloadVerifier` immutable; if verifier needs replacement (e.g. new proof system), requires deploying new registry.  
   - Possibly acceptable; document migration path.

10. Informational: First Registration Not Signed  
    - Trust anchored entirely in attestation binding; acceptable but must be documented for integrators expecting signature-based bootstrap.

11. Informational: Absence of Event for Key Rotation Distinction  
    - `CVMUpdated` emitted both for plain reattestation and rotation; off-chain indexers must derive rotation by diffing identity hashes.  
    - Enhancement: Add `CVMIdentityRotated(oldHash, newHash)`.

---

## 10. Recommended Fix Summary

| Issue # | Action |
|---------|--------|
| 1 | Implemented: `reattestCvmWithTpm` uses `getMeasurement` (normalization applied). |
| 2 | Implemented: `_rotateCvmIdentity` now copies `tpmAk`. |
| 3 | Enforce freshness in `setCollateralTTL`. |
| 4 | Add bounds: e.g. `1 day ≤ TTL ≤ 90 days`. |
| 5 | Revert on mismatched `cloudType` / `teeType` during existing registration. |
| 7 | Add explicit min length check in `_parseIdentityFromTpmData`. |
| 8 | Optional `revokeCvm()` + `CVMRevoked` event. |
| 11 | Add dedicated rotation event. |

---

## 11. Integration Notes

- Consumers should call `hasRegistered` then `checkTEEValidity` & `checkTPMValidity` gating privileged actions.
- For identity-signed operations, include:
  - Domain prefix
  - Current nonce (query via `nonces`)
  - Context payload
- Always re-derive `cvmIdentityHash` client-side from `Pubkey` to avoid mismatches.

---

## 12. Future Extensions (Optional)

| Extension | Rationale |
|-----------|-----------|
| Multi-TEE Aggregation | Support workloads spanning multiple enclaves. |
| Attestation Versioning | Track historical measurement hashes for audit. |
| Slashing / Economic Bonding | Penalize stale or revoked identities in higher-level protocols. |
| Cached Proof Compression | Gas-optimized re-use of previously verified certificate chains. |

---

## 13. Summary

`CVMRegistry` provides a lightweight state layer tying verified enclave workload identities to integrity & freshness metadata, delegating heavy cryptographic verification to `WorkloadVerifier`. Addressing the highlighted issues (notably measurement normalization during TPM-only re-attestation and key rotation state completeness) will harden correctness and operator ergonomics.
