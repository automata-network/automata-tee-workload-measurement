# CVM Registry Primer

Status: Draft  
Scope: Overview of `CVMRegistry` contract, lifecycle, trust assumptions, and identified issues (including `WorkloadVerifier` interactions).

---

## 1. Purpose

`CVMRegistry` maps a Confidential VM (CVM) workload identity (a TPM-generated public key) to:
- Its attestation configuration (TEE type, cloud provider)
- The latest trusted measurement hash
- Expiration timestamp (single TTL-based validity window)
- Attestation artifacts (TEE output, TPM Attestation Key)
- AK binding (one-to-one mapping between Attestation Key and identity)

The CVM identity key is certified by the TPM Attestation Key via TPM2_Certify, guaranteeing the CVM owner cannot read the private key - signatures can only be generated from within the CVM.

Once registered, the CVM's identity key can sign authorized messages (with domain separation) enabling downstream onchain actions gated by workload integrity + liveness (via TTL).

---

## 2. Key External Dependencies

| Component | Responsibility |
|----------|----------------|
| `WorkloadVerifier` | Verifies TEE report (on-chain or via ZK) + TPM quote + PCR measurements. Produces `TEEVerifiedData` and canonical measurement. |
| `ITpmAttestation` | Verifies TPM quote, extracts PCRs, and verifies TPM2_Certify certification of CVM identity keys. |
| TEE Attestation libs (DCAP / SNP / ZK) | Provide raw TEE attestation validation primitives. |

---

## 3. Core Data Structures

### `CVMConfig`
```solidity
struct CVMConfig {
    TEEType teeType;
    CloudType cloudType;
    uint64 expiredAt;                // Single expiration timestamp
    bytes32 measurementHash;
    CVMIdentity cvmIdentity;         // Workload identity key
    CertPubkey tpmAk;                // TPM Attestation Key
    bytes teeAttestationOutput;      // Cached TEE attestation output
}
```

### `CVMIdentity`
```solidity
struct CVMIdentity {
    bytes tpmtPublic;                // TPM public key in TPMT_PUBLIC format
    SignatureAlgorithm sigAlgo;      // Signature scheme and hash algorithm
}
```

### `CVMIdentityCertification`
```solidity
struct CVMIdentityCertification {
    bytes certInfo;                  // TPMS_ATTEST from TPM2_Certify
    bytes akCertificationSig;        // AK signature over certInfo
}
```

### Internal Mappings
- `_configs[bytes32 cvmIdentityHash] => CVMConfig`
- `_usedTeeReports[bytes32 teeHash] => bool` (replay protection for TEE reports)
- `_usedTpmQuotes[bytes32 tpmHash] => bool` (replay protection for TPM quotes)
- `_revokedCvmIdentities[bytes32 cvmIdentityHash] => bool` (tracks rotated identities)
- `_akBindings[bytes32 akHash] => bytes32 cvmIdentityHash` (one-to-one AK binding)

### Identity Hash
Public key is extracted from `tpmtPublic` using `CVMShared.extractPubkeyFromTpmtPublic()`, then:
```solidity
keccak256(abi.encodePacked(
    sigAlgo.scheme,
    pubkey.params,
    sigAlgo.hashAlgo,
    pubkey.data
))
```

---

## 4. Lifecycle

### 4.1 Registration (`registerCvm`)
1. Extract public key from `cvmIdentity.tpmtPublic` and compute `cvmIdentityHash`.
2. Verify CVM identity is not already registered or revoked.
3. Call `workloadVerifier.verifyAttestation(...)`:
   - Verifies: TEE report, TPM quote, PCRs.
   - Returns `teeOutput`, `teeVerifiedData`, `measurement`.
4. Verify AK is not already bound to another identity.
5. Call `tpmAttestation.verifyTpmKeyCertification(...)`:
   - Verifies CVM identity key is certified by AK via TPM2_Certify.
   - Parameters: `certInfo`, `akCertificationSig`, `tpmtPublic`, verified AK from TEE.
6. Compute measurement hash from `measurement`.
7. Persist config:
   - `expiredAt = block.timestamp + teeTTL` (default 30 days if `teeTTL == 0`)
   - Store: identity, measurement hash, TEE output, TPM AK, cloud/TEE types
8. Bind AK to CVM identity: `_akBindings[akHash] = cvmIdentityHash`
9. Mark TEE report and TPM quote as used (replay protection)
10. Emit `CVMRegistered(cvmIdentityHash)`.

**No signature from the CVM identity is required** for initial registration—trust is bootstrapped entirely by attestation and TPM2_Certify certification.

### 4.2 Refresh (`refreshCvm`)
Extends CVM validity with fresh TEE and TPM attestations.

Use when:
- CVM validity has expired or is about to expire
- Need to extend lifetime with fresh attestation collaterals

Steps:
1. Verify CVM is registered (`hasRegistered(cvmIdentityHash)`).
2. Verify TEE report and TPM quote not previously used (replay protection).
3. Call `workloadVerifier.verifyAttestation(...)`:
   - Verifies fresh TEE report, TPM quote, PCRs.
4. Verify AK binding matches registered identity:
   - Prevents AK swap attacks.
5. Compute new measurement hash.
6. Update config:
   - `expiredAt = block.timestamp + teeTTL`
   - Update `measurementHash` and `teeAttestationOutput`
   - Do NOT update: `cvmIdentity`, `tpmAk`, `teeType`, `cloudType`
7. Mark new TEE report and TPM quote as used.
8. Emit `CVMRefreshed(cvmIdentityHash)`.

**Important**: No signature required. Does NOT support identity rotation (use `rotateCvmIdentityKey` instead). This is the only way to extend validity after TTL expires.

### 4.3 Key Rotation (`rotateCvmIdentityKey`)
Rotates the CVM identity key while TEE report is still valid.

Use when:
- Need to rotate identity key without full re-attestation
- TEE report is still fresh (not expired)

Steps:
1. Verify CVM is registered and not expired (`block.timestamp <= config.expiredAt`).
2. Extract new public key from `newCvmIdentity.tpmtPublic` and compute new identity hash.
3. Verify new identity is not revoked or already registered.
4. Call `tpmAttestation.verifyTpmKeyCertification(...)`:
   - Uses stored `config.tpmAk` as the certifying key.
   - Verifies new identity key is certified by same TPM.
5. Copy configuration to new identity hash:
   - Preserve all fields: `teeType`, `cloudType`, `expiredAt`, `measurementHash`, `teeAttestationOutput`, `tpmAk`
   - Update `cvmIdentity` to new identity
6. Revoke old identity: `_revokedCvmIdentities[oldHash] = true`
7. Update AK binding: `_akBindings[akHash] = newCvmIdentityHash`
8. Emit `CVMIdentityRotated(oldHash, newHash)`.

**Important**: Saves gas by reusing existing attestation data. New identity key must be certified by same AK.

---

## 5. Freshness Semantics

### Single TTL Model
- **Default TTL**: 30 days (2,592,000 seconds) - `DEFAULT_TEE_TTL`
- **Expiration**: `expiredAt = block.timestamp + teeTTL`
- **Validity Check**: `block.timestamp <= expiredAt`

### Custom TTL
- Can be specified at registration or refresh via `teeTTL` parameter
- If `teeTTL == 0`, defaults to 30 days

### Extending Validity
- **Only option**: Call `refreshCvm()` with fresh TEE + TPM attestations
- Updates `expiredAt` to `block.timestamp + teeTTL`
- Key rotation does NOT extend validity (preserves existing `expiredAt`)

---

## 6. Message Domain Separation

Applications using the `CVMSignature` base contract can construct domain-separated messages:
```
abi.encodePacked(bytes(prefix), block.chainid, address(this), userData)
```

### Default Prefix
- `"CVM_WORKLOAD_USER_MESSAGE"` - For general application-specific payloads

### Custom Prefixes
Applications can use `_generateMessageWithCustomPrefix(prefix, userData)` to distinguish different message types within their protocol.

### Security Properties
- **Contract binding**: `address(this)` prevents cross-contract replay
- **Chain binding**: `block.chainid` prevents cross-chain replay
- **Operation-specific**: Custom prefixes prevent confusion between message types

**Important**: CVMRegistry does NOT provide nonce-based replay protection for application messages. Applications MUST implement their own replay protection mechanism.

---

## 7. Measurement Handling

Canonical measurement = hash of `Measurement` struct where `WorkloadVerifier.getMeasurement`:
- Converts measured PCRs to final set
- Zeroes `tdx.rtmr3` (contains reboot-variant UUID) to stabilize measurement across restarts.

Registry stores only `bytes32 measurementHash` (digest). Consumers should treat this as workload integrity anchor.

---

## 8. Security & Trust Assumptions

| Aspect | Implementation | Security Property |
|--------|----------------|-------------------|
| **Identity Binding** | TPM2_Certify certification | CVM identity key certified by AK; guarantees private key cannot be read by CVM owner |
| **AK Binding** | One-to-one mapping `_akBindings[akHash] => cvmIdentityHash` | Prevents AK reuse across multiple identities; detects AK swap attacks |
| **Replay Protection (Attestations)** | Hash-based tracking: `_usedTeeReports`, `_usedTpmQuotes` | TEE reports and TPM quotes cannot be reused |
| **Replay Protection (App Messages)** | NOT PROVIDED | Applications MUST implement their own nonce/timestamp-based protection |
| **Identity Revocation** | `_revokedCvmIdentities[cvmIdentityHash] => bool` | Rotated identities cannot be re-registered |
| **Upgradeability** | Immutables (`workloadVerifier`, `tpmAttestation`) fixed at deployment | Cannot bypass verification by swapping verifier contracts |
| **Key Rotation** | TPM2_Certify with stored AK | New identity must be certified by same TPM (cannot rotate to arbitrary key) |
| **Measurement Normalization** | Zeros TDX rtmr3 in `WorkloadVerifier.getMeasurement()` | Stable measurement hash across CVM reboots |

---

## 9. Current Design & Outstanding Considerations

### Resolved in Current Implementation

1. ✅ **Measurement Normalization**: `refreshCvm` and `registerCvm` both use `workloadVerifier.verifyAttestation()` which applies measurement normalization (zeroing TDX rtmr3).

2. ✅ **Key Rotation Preservation**: `rotateCvmIdentityKey` properly copies all configuration fields including `tpmAk`.

3. ✅ **Identity Revocation**: Rotated identities are marked in `_revokedCvmIdentities` to prevent re-registration.

4. ✅ **Rotation Event**: `CVMIdentityRotated(oldHash, newHash)` event distinguishes rotation from refresh.

5. ✅ **TPM2_Certify Security**: Identity keys certified by AK guarantee private key cannot be read by CVM owner.

6. ✅ **AK Binding Enforcement**: One-to-one mapping prevents AK reuse and detects swap attacks.

### Deliberate Design Decisions

1. **No Built-in Message Replay Protection**
   - CVMRegistry provides replay protection ONLY for TEE reports and TPM quotes during registration/refresh.
   - Applications MUST implement their own nonce/timestamp-based replay protection.
   - Rationale: Different applications have different replay protection needs (nonces, timestamps, merkle proofs, etc.).

2. **Unbounded TTL Inputs**
   - Currently accepts any `teeTTL` value (including 0 or excessively large values).
   - Enhancement: Consider enforcing bounds (e.g., `1 day <= TTL <= 90 days`).

3. **No Explicit Revocation Before Expiry**
   - Cannot manually revoke an identity before TTL expires (must wait for natural expiration).
   - Enhancement: Consider adding `revokeCvm()` function requiring signature or owner authorization.

4. **Immutable WorkloadVerifier Reference**
   - `workloadVerifier` is immutable; changing verification logic requires new registry deployment.
   - Rationale: Security over flexibility - prevents verification bypass attacks.
   - Migration path: Deploy new registry, applications point to new contract.

5. **Silent Parameter Mismatch on Re-registration**
   - `registerCvm` allows re-registration with potentially different `cloudType`/`teeType` without explicit validation.
   - Enhancement: Revert if parameters don't match existing configuration.

6. **First Registration Not Signed**
   - Initial `registerCvm` does not require signature from CVM identity.
   - Rationale: Trust bootstrapped via attestation + TPM2_Certify certification.
   - Documented for integrators to understand trust model.

---

## 10. Potential Enhancements

| Enhancement | Priority | Description |
|-------------|----------|-------------|
| TTL Bounds | Medium | Enforce minimum (e.g., 1 day) and maximum (e.g., 90 days) TTL values |
| Explicit Revocation | Low | Add `revokeCvm()` function with signature requirement or owner control |
| Parameter Validation | Low | Revert if `cloudType`/`teeType` mismatch during re-registration |
| Multi-TEE Aggregation | Future | Support workloads spanning multiple enclaves |
| Attestation Versioning | Future | Track historical measurement hashes for audit trails |
| Cached Proof Compression | Future | Gas-optimized re-use of verified certificate chains |

---

## 11. Integration Notes

### For Application Developers

1. **Check CVM Validity**:
   ```solidity
   require(cvmRegistry.hasRegistered(cvmIdentityHash), "Not registered");
   require(cvmRegistry.checkCvmValidity(cvmIdentityHash), "CVM expired");
   ```

2. **Validate Measurement**:
   ```solidity
   bytes32 measurementHash = cvmRegistry.getMeasurementHash(cvmIdentityHash);
   require(allowedMeasurements[measurementHash], "Invalid measurement");
   ```

3. **Verify Signatures** (inherit from `CVMSignature`):
   ```solidity
   // Construct domain-separated message
   bytes memory message = _generateMessage(abi.encodePacked(nonce, userData));

   // Verify signature
   CVMIdentity memory identity = cvmRegistry.getCvmIdentity(cvmIdentityHash);
   require(_verifySignature(identity, signature, message), "Invalid signature");
   ```

4. **Implement Replay Protection**:
   ```solidity
   // Example: nonce-based
   require(!usedNonces[cvmIdentityHash][nonce], "Nonce used");
   usedNonces[cvmIdentityHash][nonce] = true;
   ```

5. **Compute Identity Hash** (client-side):
   ```solidity
   // Extract pubkey from tpmtPublic
   CertPubkey memory pubkey = CVMShared.extractPubkeyFromTpmtPublic(cvmIdentity.tpmtPublic);

   // Compute hash
   bytes32 identityHash = keccak256(abi.encodePacked(
       cvmIdentity.sigAlgo.scheme,
       pubkey.params,
       cvmIdentity.sigAlgo.hashAlgo,
       pubkey.data
   ));
   ```

### For CVM Agent Developers

1. **Registration**: Call `registerCvm()` with:
   - Fresh TEE attestation report
   - TPM quote with PCR measurements
   - CVM identity key (TPM-generated)
   - TPM2_Certify certification of identity key

2. **Refresh**: Call `refreshCvm()` before expiration with:
   - Fresh TEE attestation report
   - Fresh TPM quote

3. **Key Rotation**: Call `rotateCvmIdentityKey()` while valid with:
   - New TPM-generated identity key
   - TPM2_Certify certification of new key

---

## 12. Summary

`CVMRegistry` provides a lightweight state layer tying verified CVM workload identities to integrity and freshness metadata. The current implementation uses TPM2_Certify for strong identity binding, ensuring the CVM owner cannot read the private key. Applications inherit from `CVMSignature` for signature verification and must implement their own replay protection. The registry delegates heavy cryptographic verification to `WorkloadVerifier` while managing identity lifecycle, AK bindings, and attestation freshness.
