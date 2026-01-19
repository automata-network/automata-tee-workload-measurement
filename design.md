# CVM Workload Onchain Registry Design

The CVM Workload Onchain Registry plays a role in the following:

1. Maintaining a set of user-registered CVM credentials to identify the VM.
    - TEE reports (Intel TDX Quotes or AMD SEV-SNP Reports), along with TPM quotes, to confirm user credential is provisioned by TPM in genuine TEE hardware.
2. Once a credential has been registered, it is used to authenticate CVM onchain activities.
    - Consumer contracts can query the Registry to determine the validity of the registered credential.
    - The validity of a registered identity is determined by factors such as the age of TEE Reports (time elapsed since recent submissions), and values in the TEE Report Body (such as Intel TDX TCB Status etc) that should adhere to the security policies set by projects.

---

## Definitions

- Machine Identity

In our design, we use the TPM Attestation Key (AK) as the trust anchor of the machine’s identity. The AK has the privileges to: (1) rotate CVM identity keys; (2) update workload measurements; and (3) refresh TEE reports.

- CVM Identity Signing Key

Simply referred as “CVM Identity”. This is the alias key certified by the TPM AK for message signing. As per TPM convention, it is advisable to generate app-specific keys using the Owner hierarchy for generic message signing. 

CVM Identity can be provisioned with the ECC scheme on the p256 curve, which is cheaper to verify onchain either with RIP 7212 or EIP 7951 precompiles, comparing with RSA.

See Appendix 1 to learn more about `TPM2_Certify`.

---

## Rationale

A TEE Attestation Report provides evidence about the enclave environment for a given CVM workload. Application contracts are encouraged to make use of the information to tailor security policies as an additional factor to decide whether they could trust the CVM instance or not.

TEE Reports do not permanently represent the state of a CVM, so regular re-attestations is recommended for better security. For this current iteration, our CVM Registry either (1) let users to provide their desired TTL or (2) defaults to an admin-specified TTL to determine the validity of TEE reports. All authentications signed by the CVM identity key can be considered valid as long as it is done so at the time when the TEE report is still “valid”.

The TPM attestation key mainly signs the workload measurements and certifies the CVM Identity Key. Therefore any updates to the machine specific configurations (except for the CVM Identity), must go through the “CVM Refresh” workflow.

The following rules currently applied to the CVM Registry:

- TEE Attestation Report and TPM Quotes can only be used individually once.
    - Attackers cannot bind a new TEE attestation report with an old TPM Quote (and vice versa).
- Each machine can only have one CVM identity registered at a time. In other words, a single TPM AK cannot bind with more than one CVM Identity Key.
- Admin-configured TTL is not an absolute guarantee that the TEE report accurately represent the state of the CVM. Frequent TEE refreshes should improve security.
- Both the TPM Attestation and CVM Identity Keys must be derived from the same TPM.
- CVM Identity Keys cannot be shared by multiple CVMs. It is (impossible? Inadvisable) to use another TPM keys on a different machine. (Not sure if migration is possible).

---

## Interfaces

The following constants and methods will be introduced.

```solidity
contract CVMVerifier {
  /// The default TTL (in seconds) for TEE Reports (30 days, tentative)
  uint64 constant DEFAULT_TEE_TTL = 2_592_000;
	
	/// Mapping between a given CVM and its config
	mapping (bytes32 cvmIdentityHash => CVMConfig) _configs;
	
	mapping (bytes32 cvmIdentityHash => uint256) _nonces;
	
	/// Defined in IWorkloadVerifier
	struct WorkloadCollaterals {
	  // verified by tpmSignature
    bytes tpmQuote;
    bytes tpmSignature;
    // verified by tpmQuote
    MeasureablePcr[] pcrs;
    // tdx&gcp: uuid
    bytes reportId;
    // gcp: akPub
    // azure: varDataJson
    bytes akPub;
    // gcp: certs
    // azure: empty
    bytes[] certs;
	}
	
	// CertPubkey and SignatureAlgorithm as defined by the latest changes made
	// in automata-tpm-attestation in LibX509
	// https://github.com/automata-network/automata-tpm-attestation/blob/1a3ab2bc4886ac5313365f94e3d60dcf01fd9c41/src/lib/LibX509.sol#L56-L79
	
	/// @dev pubkey algo and params, and signature algorithm hashAlgo and schemes
	/// are TPM Constants as defined in pages 26-28 of
	/// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
	
	/// @dev this is basically the truncated structure of TPMT_PUBLIC
	/// currently used for both X509 key and TPM Attestation Keys
	/// @dev for future improvement, consider defining TPMT_PUBLIC data structure
	/// to represent all TPM keys only.
	struct CertPubkey {
	    uint16 algo;
	    uint16 params;
	    bytes data;
	}
	
	struct SignatureAlgorithm {
    uint16 scheme;
    uint16 hashAlgo;
  }
	
	struct CVMConfig {
	  TeeType tee;
	  CloudType cloud;
	  /// the timestamp after which the CVMIdentity is no longer trusted
	  /// timestamp + specified TTL (or DEFAULT_TEE_TTL)
	  uint64 expiredAt;
	  bytes32 measurementHash;
	  CVMIdentity cvmIdentity;
	  CertPubkey tpmAk;
	  /// The encoded output obtained from onchain TEE Verification contract
	  /// This contains information about the TEE, including TEE Report content
	  /// such as TD10 Report or AMD SEV SNP Report
	  bytes teeAttestationOutput;
	}
	
	/// @dev must explicitly provide this struct as a separate argument
	struct CVMIdentity {
	  bytes tpmtPublic; // Marshalled TPMT_PUBLIC value of the CVMIdentity key
	  SignatureAlgorithm sigAlgo;
	}
	
	/// @dev this struct contains the field values required to verify
	/// @dev that CVMIdentity key is certified by TPM AK from the same machine.
	struct CVMIdentityCertification {
	  bytes akCertificationSig; // AK signature of certInfo
	  bytes certInfo; // TPMS_ATTEST
	}
	
	/**
	* @notice invoke this method to attest their CVM and
	* register the workload generated key as their onchain identity
	*
	* @dev must check TEE and TPM bindings
	* @dev must also check cvmIdentity key is generated by the same TPM.
	* @notice caller may optionally specifies their TTL, otherwise uses
	* DEFAULT_TEE_TTL
	*
	* @dev creates cvmConfigs[cvmIdentityHash] => cvmConfig
	*/
	function registerCvm(
    CloudType cloudType,
    TEEType teeType,
    TeeReportType teeReportType,
    uint64 teeTTL,
    bytes calldata teeAttestationReport,
    CVMIdentity calldata cvmIdentity,
    CVMIdentityCertification calldata cvmCertification,
    WorkloadCollaterals calldata wc
	)
	
	/**
	* @notice invoke this method to resubmit the TEE report for existing
	* CVMs
	* 
	* @dev must make sure that the TPM quote is signed by the same AK from
	* registration
	*
	* @dev must prevent re-using BOTH TEE and TPM reports
	*
	* @dev measurement updates occur here, but CVMIdentity rotation flow
	* must go through the rotateCvmIdentityKey() call.
	*
	* @dev updates cvmConfigs[cvmIdentityHash] => cvmConfig
	*/
	function refreshCvm(
	  bytes32 cvmIdentityHash,
    TeeReportType teeReportType,
    bytes calldata teeAttestationReport,
    WorkloadCollaterals calldata wc
	)
	
	/**
	* @notice call this method if:
	* (0) TEE report is still fresh, saves gas
	* (1) Users intend to rotate their identity keys
	*
	* @dev must check block.timestamp <= config.expiredAt
	*
	* @dev the entire config will be re-mapped using the new CVM identity hash
	* @dev cvmConfigs[updateCvmIdentityHash] => cvmConfig
	* @dev delete / unset cvmConfigs[cvmIdentityHash]
	*
	*/
	function rotateCvmIdentityKey(
	  bytes32 cvmIdentityHash,
	  bytes calldata signature,
	  CVMIdentity calldata newCvmIdentity,
	  CVMIdentityCertification calldata newCvmCertification
	) external;
	
	**/// ===== HELPER METHODS =====
	
	// at the current block.timestamp is the registered CVM still valid
	// true = valid
	// false = expired
	function checkCvmValidity(bytes32 cvmIdentityHash)
		public view returns (bool valid);
	
	function getMeasurementHash(bytes32 cvmIdentityHash)
	  public view returns (bytes32 hash);
	  
	function getCvmIdentity(bytes32 cvmIdentityHash)
	  public view returns (CVMIdentity memory identity);
	
	/// @notice use this method if you need to load everything
	/// about the registered CVM
	function getCvmConfig(bytes32 cvmIdentityHash)
	  public view returns (CVMConfig memory config);**
}

```

---

## CVM Identity Bytes Specification

The identity of the CVM should mainly contain the public portion of an asymmetric key generated using the [Owner hierarchy](https://github.com/nokia/TPMCourse/blob/master/docs/keys.md#creating-keys) by the TPM, which is enabled with persistence (re-usable even after CVM reboots). Along with the public key raw value, it also contains metadata describing the signature and hashing algorithms of the key. Algorithms are denoted using TPM constants as defined in the official [TPM2 documentation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf).

The identity therefore shall be encoded in the format below:

```
encoded_cvm_identity = bytes2 sig_scheme || bytes2 pubkey_params || bytes2 hash_algo || <pubkey_value>
```

Currently, we primarily supports NIST P256 **uncompressed (0x04 prefixed)** keys using the SHA256 hash. The identity should look like the following:

```
SIG_SCHEME = 0x0018 (TPM_ALG_ECDSA)
PUBKEY_PARAMS = 0x0003 (TPM_ECC_NIST_P256)
HASH_ALGO = 0x000B (TPM_ALG_SHA256)
PUBKEY_VALUE = 0x04 || x || y (65 bytes)

encoded_cvm_identity = 0x0018 || 0x0003 || 0x000B || 0x04 || x || y
```

To keep track of registered CVM credentials and configs onchain, the `keccak256` hash of the identity is used.

```
cvm_identity_hash = keccak256(encoded_cvm_identity)
```

---

## Signature Verification using CVM

Upon successful registration or refresh of a CVM Identity, the CVM workload can authenticate all its onchain activities by signing the payload with its CVM Identity key, as long as it is done so within the TEE validity.

It is recommended that the signing message to conform with the structure below:

```solidity
// hash function is dependent on the specified signing hashAlgo 
// for the identity
bytes GENERIC_USER_WORKLOAD_MESSAGE = hash(
  "CVM_WORKLOAD_USER_MESSAGE",
  uint256 chainId,
  address verifyingContract,
  bytes user_data, // app-specfic payload
);
```

### CVMSignature Base Contract

CVM Identity Message Signing methods can be integrated into application contracts by simply importing the CVMSignature Base Contract.

```solidity
/// @title CVM Signature Base Contract
/// @notice This contract provides a template,
/// generating messages to be signed by a CVM Identity Key.
abstract contract CVMSignature {

    /// @dev must overwrite this method indicate the address of the CVMRegistry
    function cvmRegistry() public view virtual returns(address);

    function _generateMessage(bytes memory userData) internal view virtual returns (bytes memory) {
        return _generateMessageWithCustomPrefix("CVM_WORKLOAD_USER_MESSAGE", userData);
    }

    function _generateMessageWithCustomPrefix(string memory prefix, bytes memory userData)
        internal
        view
        virtual
        returns (bytes memory)
    {
        return abi.encodePacked(bytes(prefix), block.chainid, address(this), userData);
    }

    function _verifySignature(
        CVMIdentity memory cvmIdentity,
        bytes memory signature,
        bytes memory message,
        address verifier
    ) internal view virtual returns (bool) {
        // @dev: must check CVMIdentity is still valid
        bool cvmIsValid = ICVMRegistry(cvmRegistry()).checkCvmValidity();
        require(cvmIsValid, "CVM has expired");
        
        return LibX509Verify.verifySignature(
            cvmIdentity.pubkey,
            cvmIdentity.sigAlgo,
            message,
            signature,
            verifier
        );
    }
}
```

**Note: The consumer contract is responsible for implementing their own replay protection mechanism.**

**Signature Format:**

CVM Identities that use the p256 signature scheme should simply encode signature bytes by concatenating r and s values, with a total size at 64 bytes.

```solidity
bytes signature = abi.encodePacked(r, s);
```

---

## Workflows

### CVM Registration:

1. The provided CVM identity and TPM AK must be brand new. `cvmConfigs[cvmIdentityHash]` uninitialized.
    1. Reverts otherwise, users should proceed to the “CVM Refresh” flow instead.
2. TEE Reports and TPM Quotes sent to the Workload Verifier contract to be checked and verified.
    1. Checks whether both hash(TEE) and hash(TPM) have been previously flagged.
        1. Reverts otherwise, because it detects a replay.
    2. Verifies the integrity of Intel TDX Quote or AMD SEV SNP Report
    3. Verifies whether the provided TPM Attestation Key is legitimate (Azure VMs are exempt from this step because the AK itself is bounded to theTEE report)
    4. Verifies the signature of the TPM quote against the TPM Attestation Key.
    5. Reads the measured PCRs from the collateral, and check against the PCR selections and digest in the TPM quote.
    6. Checks binding between TEE and TPM reports.
    7. At this point, the contract should flag both hash(TEE) and hash(TPM) to prevent replays a `mapping(bytes32) ⇒ bool` .
    8. The contract must check whether the CVM Identity Key is derived in the same TPM as the TPM attestation key.
        1. See Appendix 1.
3. Initializes the CVM Configuration
    1. ~~Use DEFAULT_TEE_TTL.~~   Set `config.expiredAt = block.timestamp + DEFAULT_TEE_TTL`. 
    2. Stores essential information about the workload:
        1. CVM Identity (public portion of an asymmetric key provisioned within the VM)
        2. The content of the TEE Attestation Report (e.g. TD 1.0 Report or AMD SEV-SNP Attestation Report)
        3. The measurement hash returned by the Workload Verifier.

### Key Rotation:

This flow is self-explanatory. All it does, is allowing the CVM user to rotate their CVM identity, given that TEE Report is still fresh.

1. Checks `block.timestamp ≤ config.expiredAt`.
    1. Reverts otherwise.
2. The contract must check whether the new CVM Identity Key is derived in the same TPM as the TPM attestation key.
    1. See Appendix 1.
3. Remaps the CVM Configuration to be indexed by the new CVM identity hash, and deletes the old CVM Identity configuration mapping.

### CVM Refresh:

The flow is very similar with “CVM Registration” but applies to only registered CVM Identities.

1. The provided CVM Identity hash must already be registered.
    1. Reverts otherwise.
2. TEE Reports and TPM Quotes sent to the Workload Verifier contract to be checked and verified.
    1. Checks whether both hash(TEE) and hash(TPM) have been previously flagged.
        1. Reverts otherwise, because it detects a replay.
    2. Verifies the integrity of Intel TDX Quote or AMD SEV SNP Report
    3. Checks whether the provided TPM Attestation Key matches with the registered AK.
    4. Verifies the signature of the TPM quote against the TPM Attestation Key.
    5. Reads the measured PCRs from the collateral, and check against the PCR selections and digest in the TPM quote.
    6. Checks binding between TEE and TPM reports.
    7. At this point, the contract should flag both hash(TEE) and hash(TPM) to prevent replays a `mapping(bytes32) ⇒ bool` .
3. Updates the CVM Configuration
    1. Renews `config.expiredAt`
    2. Update the workload information:
        1. The measurement hash
        2. The TEE Report content

---

## User Consumer Contract General Guidelines

- Project or contract owners shall maintain a list of measurements that fulfill the requirements of their use case, which is also known as **golden measurements**.
    - Measurement provides information about the workload, such as disk state, boot measurements etc.
    - A CVM whose measurement matches the golden measurement indicates that it is running the workload as intended.
- The project user can proceed to register their CVM via the Registry, which stores a credential that can be used to identify the user’s CVM workload.
- The consumer contract can query the Registry for information about registered users, which can be used to determine the validity of their identity as per the project’s own security policy.
- The Consumer Contract can use the queried information to determine the validity of the identity, such as checking TTL, registered measurement hash, etc.
- Once the CVM credentials have deemed valid, the consumer contract can proceed to verify the signed message and its signature by invoking the internal `_verifySignature()` method. (Note: Consumer contracts should inherit the `CVMSignature` base contract)

### Sample User Contract

```solidity
import {
  CVMIdentity,
  ICVMRegistry
} from "@automata-network/tee-workload-measurement/interfaces/ICVMRegistry.sol";
import {CVMSignature} from "@automata-network/tee-workload-measurement/usecases/bases/CVMSignature.sol";

contract SampleCVMAuth is CVMSignature {
    ICVMRegistry public immutable cvmRegistry;
    address public owner;
    address public p256Verifier;
    mapping(bytes32 goldenMeasurementHash => bool) public goldenMeasurements;

    constructor(address _cvnRegistry, address _p256Verifier) {
        owner = msg.sender;
        cvmRegistry = ICVMRegistry(_cvnRegistry);
        p256Verifier = _p256Verifier;
    }

    event GoldenMeasurementRegistered(bytes32 indexed measurementHash);
    event GoldenMeasurementRemoved(bytes32 indexed measurementHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    function addGoldenMeasurement(bytes32 measurementHash) external onlyOwner {
        require(!goldenMeasurements[measurementHash], "Measurement already registered");
        goldenMeasurements[measurementHash] = true;
        emit GoldenMeasurementRegistered(measurementHash);
    }

    function removeGoldenMeasurement(bytes32 measurementHash) external onlyOwner {
        require(goldenMeasurements[measurementHash], "Measurement not registered");
        delete goldenMeasurements[measurementHash];
        emit GoldenMeasurementRemoved(measurementHash);
    }

    /**
     * @notice Checks if a provided a CVM is registered with valid measurements
     */
    function checkCvmMeasurements(bytes32 cvmIdentityHash) public view returns (bool) {
        bytes32 measurementHash = cvmRegistry.getMeasurementHash(cvmIdentityHash);
        return goldenMeasurements[measurementHash];
    }

    function checkCVMSignature(bytes32 cvmIdentityHash, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        // Step 1: Check CVM Identity is registered and contained valid measurements
        bool cvmMeasurementValid = checkCvmMeasurements(cvmIdentityHash);
        if (!cvmMeasurementValid) {
            return false;
        }

        // Step 2: Verify CVM Signature
        CVMIdentity memory cvmIdentity = cvmRegistry.getCvmIdentity(cvmIdentityHash);
        address verifier = cvmIdentity.sigAlgo.scheme == TPMConstants.TPM_ALG_ECDSA ? p256Verifier : address(0);
        verified = _verifySignature(cvmIdentity, signature, message, verifier);
        
        // application business logic goes here...
    }
}    
```

---

## Appendix 1:  CVM Identity Key TPM Binding Check Flow

### Overview

The TPM Binding Check verifies that a CVM Identity key was generated by and resides within the same TPM hardware as the registered Attestation Key (AK). This is accomplished using the TPM2_Certify command, which produces:

1. **certifyInfo** — A `TPMS_ATTEST` structure containing the certified key's "name"
2. **signature** — The AK's signature over certifyInfo

By verifying this certification on-chain, we establish that the CVM Identity private key is TPM-managed and cannot be exported, ensuring that any signature from this key must originate from the registered CVM hardware.

---

### Required Inputs

**Provided by CVM Client:**

| Input | Description |
| --- | --- |
| `certifyInfo` | Raw bytes of TPMS_ATTEST structure from TPM2_Certify |
| `akSignature` | AK's signature over certifyInfo |
| `tpmtPublic` | Marshalled TPMT_PUBLIC of the CVM Identity key |
| `cvmIdentity` | The CVM Identity public key (for matching) |

**Already Stored On-Chain (from registration):**

| Stored | Description |
| --- | --- |
| `config.tpmAk` | The TPM Attestation Key public key |
| `config.cvmIdentity` | The registered CVM Identity (for rotation: the current identity) |

---

### Verification Workflow

### Step 1: Verify AK Signature over CertifyInfo

The AK signature proves that the certifyInfo structure was genuinely produced by the TPM associated with the registered AK.

**Process:**

1. Retrieve the stored `config.tpmAk` (Attestation Key public key)
2. Determine the signature algorithm (RSASSA or ECDSA based on AK type)
3. Verify `akSignature` over `certifyInfo` using the AK public key
4. If verification fails, reject the certification

**Security Note:** The AK was already validated during CVM registration via TEE attestation. We trust it as the machine's identity anchor.

---

### Step 2: Parse CertifyInfo and Extract Certified Key Name

The `certifyInfo` is a `TPMS_ATTEST` structure. For TPM2_Certify, it has type `TPM_ST_ATTEST_CERTIFY` (0x8017).

**TPMS_ATTEST Structure:**

```
┌────────────────────────────────────────────────────────────┐
│ magic             : 4 bytes   (0xff544347 = "\\xffTCG")     │
│ type              : 2 bytes   (0x8017 for CERTIFY)         │
│ qualifiedSigner   : TPM2B_NAME (2-byte size + name)        │
│ extraData         : TPM2B_DATA (2-byte size + data)        │
│ clockInfo         : 17 bytes  (clock, reset, restart, safe)│
│ firmwareVersion   : 8 bytes                                │
│ attested          : TPMS_CERTIFY_INFO                      │
│   ├─ name         : TPM2B_NAME  ← CERTIFIED KEY'S NAME     │
│   └─ qualifiedName: TPM2B_NAME                             │
└────────────────────────────────────────────────────────────┘

```

**Process:**

1. Verify `magic` == 0xff544347
2. Verify `type` == 0x8017 (TPM_ST_ATTEST_CERTIFY)
3. Parse through variable-length fields to locate `attested.name`
4. Extract the certified key's name (typically 34 bytes: 2-byte algorithm ID + 32-byte hash)

---

### Step 3: Compute Expected Name from TPMT_PUBLIC

The "name" of a TPM object is computed as:

```
name = nameAlg || Hash(nameAlg, marshalled_TPMT_PUBLIC)
```

For SHA256 (nameAlg = 0x000b):

```
name = 0x000b || SHA256(tpmtPublic_bytes)
```

**TPMT_PUBLIC Structure (ECC P256 example):**

```
┌────────────────────────────────────────────────────────────┐
│ type              : 2 bytes   (0x0023 = TPM_ALG_ECC)       │
│ nameAlg           : 2 bytes   (0x000b = TPM_ALG_SHA256)    │
│ objectAttributes  : 4 bytes   (key property flags)         │
│ authPolicy        : TPM2B     (2-byte size + policy bytes) │
│                                                            │
│ ─── TPMS_ECC_PARMS ───                                     │
│ symmetric.algo    : 2 bytes   (0x0010 = NULL)              │
│ scheme.scheme     : 2 bytes   (0x0018 = ECDSA)             │
│ scheme.hashAlg    : 2 bytes   (0x000b = SHA256)            │
│ curveID           : 2 bytes   (0x0003 = P256)              │
│ kdf.scheme        : 2 bytes   (0x0010 = NULL)              │
│                                                            │
│ ─── TPMS_ECC_POINT (unique) ───                            │
│ x                 : TPM2B     (2-byte size + 32 bytes)     │
│ y                 : TPM2B     (2-byte size + 32 bytes)     │
└────────────────────────────────────────────────────────────┘

```

**Process:**

1. Take the provided `tpmtPublic` bytes (already marshalled by client)
2. Extract the `nameAlg` from bytes [2:4]
3. Compute: `expectedName = nameAlg || Hash(tpmtPublic)`
4. Compare `expectedName` with the name extracted from certifyInfo (Step 2)
5. If names don't match, reject the certificatio

---

### Security Considerations

1. **Replay Protection**: Each certification should only be usable once. Consider tracking used certifyInfo hashes similar to how TEE/TPM reports are tracked.
2. **Name Algorithm Consistency**: The `nameAlg` in TPMT_PUBLIC should match the algorithm used in the certified name. Typically SHA256 (0x000b).

---

### Summary

| Step | Input | Output | Proves |
| --- | --- | --- | --- |
| 1 | certifyInfo, akSignature, stored AK | Valid/Invalid | CertifyInfo came from this TPM |
| 2 | certifyInfo | Certified key name | Which key was certified |
| 3 | tpmtPublic | Expected name | TPMT_PUBLIC matches certified name |
| 4 | tpmtPublic, cvmIdentity | Match/Mismatch | CVMidentity contains the matching TPMT_PUBLIC |

**Result:** If all steps pass, we have proven that the CVMIdentity key exists on the same TPM as the registered AK.