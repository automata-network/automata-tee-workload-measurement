// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PublicIdentity} from "./Common.sol";
import {Bytes48} from "../lib/LibBytes.sol";

/// @notice Trusted Execution Environment type supported by the platform
enum TEEType {
    /// @dev Intel Trust Domain Extensions (TDX)
    IntelTDX,
    /// @dev AMD Secure Encrypted Virtualization - Secure Nested Paging (SEV-SNP)
    AmdSevSnp
}

/// @notice Backend used to verify TEE attestation reports
enum VerificationBackendType {
    /// @dev On-chain Solidity verification
    Solidity,
    /// @dev Zero-knowledge proof via RISC Zero
    ZkRiscZero,
    /// @dev Zero-knowledge proof via Succinct SP1
    ZkSuccinct
}

/// @notice TPM report format for platform binding verification
enum TpmReportType {
    /// @dev TPM2_Quote — signed PCR snapshot with nonce binding
    TpmQuote,
    /// @dev TPM2_Certify — signed certification of a loaded key
    TpmCertify
}

/// @notice Attestation Key (AK) public key collateral format
enum AkPubCollateralType {
    /// @dev Azure: abi.encode((bytes jwt, bytes hclVarData))
    ///      jwt: Microsoft Azure Attestation-signed JWT (RS256) from /attest/TdxVm or
    ///           /attest/SevSnpVm, signed by a per-region MAA RSA-2048 key registered in
    ///           MaaKeyRegistry. JWT carries iss / x-ms-attestation-type /
    ///           x-ms-compliance-status / tdx_report_data or x-ms-sevsnpvm-reportdata claims.
    ///      hclVarData: JSON document from vTPM NV 0x01400001; contains HCLAkPub JWK.
    ///      See on-chain-registry-design.md §8.3.1, §14.9.
    AzureMaaJwt,
    /// @dev GCP: X.509 certificate chain from vTPM endorsement
    GcpCertChain,
    /// @dev AWS: abi.encode(ProgramBoundZkProof) for aws_nitrotpm.v1.
    AwsNitroTpmProof
}

/// @notice TEE attestation report with polymorphic verification data
struct TeeReport {
    /// @dev Verification backend that will process this report
    VerificationBackendType verificationBackendType;
    /// @dev TEE technology type (Intel TDX or AMD SEV-SNP)
    TEEType teeType;
    /// @dev Polymorphic data field:
    ///      - Solidity: raw TeeAttestationReport bytes
    ///      - ZkSuccinct: SP1 ZK proof
    ///      - ZkRiscZero: RISC Zero ZK proof
    bytes data;
}

/// @notice Result of TEE attestation report verification
struct TeeVerificationResult {
    /// @dev True if the TEE report signature and structure are valid
    bool valid;
    /// @dev Full report body extracted from the TEE attestation
    ///      - For Intel TDX: TD10 (584 bytes) or TD15 (648 bytes) quote body
    ///      - For AMD SEV-SNP: Full attestation report (1184 bytes)
    ///      Use TeeVerifier.extractDcapReportData() or extractSnpReportData()
    ///      to extract the 64-byte user data field from this report body.
    bytes reportData;
    /// @dev TEE technology type (Intel TDX or AMD SEV-SNP)
    TEEType teeType;
    /// @dev Stable bit set for verified Boolean TEE security attributes.
    ///      Bit 0: Intel TDX DEBUG.
    ///      Bit 1: AMD SEV-SNP POLICY.DEBUG.
    ///      Bit 2: AMD SEV-SNP POLICY.MIGRATE_MA.
    uint256 enabledTeeAttributes;
    /// @dev One-hot Intel DCAP TCB status. Zero for non-Intel TDX reports.
    uint256 intelTdxTcbStatusBit;
    /// @dev Packed AMD SEV-SNP CURRENT, REPORTED, COMMITTED, and LAUNCH TCB values.
    ///      Zero for non-AMD SEV-SNP reports.
    bytes32 amdSevSnpTcbValues;
    /// @dev Verified AMD SEV-SNP PLATFORM_INFO field. Zero for non-AMD SEV-SNP reports.
    uint64 amdSevSnpPlatformInfo;
    /// @dev Verified AMD SEV-SNP CPUID as family || model || stepping.
    ///      Zero for non-AMD SEV-SNP reports.
    uint24 amdSevSnpCpuid;
    /// @dev Verified AMD SEV-SNP attestation report format version.
    ///      Zero for non-AMD SEV-SNP reports.
    uint32 amdSevSnpReportVersion;
    /// @dev Verified AMD SEV-SNP version-5 LAUNCH_MIT_VECTOR.
    ///      Zero for report versions before 5 and for non-AMD SEV-SNP reports.
    uint64 amdSevSnpLaunchMitigationVector;
    /// @dev Verified AMD SEV-SNP version-5 CURRENT_MIT_VECTOR.
    ///      Zero for report versions before 5 and for non-AMD SEV-SNP reports.
    uint64 amdSevSnpCurrentMitigationVector;
    /// @dev Keccak-256 of the exact verified reportData bytes.
    bytes32 teeReportBytesHash;
}

/// @notice TPM report for platform binding verification
struct TpmReport {
    /// @dev Verification backend for raw Solidity evidence or a program-bound ZK proof
    VerificationBackendType verificationBackendType;
    /// @dev TPM report format (Quote or Certify)
    TpmReportType tpmReportType;
    /// @dev Polymorphic data field:
    ///      - Solidity: TpmQuoteEvidence or TpmCertifyEvidence
    ///      - ZkSuccinct: ProgramBoundZkProof
    ///      - ZkRiscZero: ProgramBoundZkProof
    bytes data;
}

struct PcrValue256 {
    uint8 pcrIndex;
    bytes32 value;
    bytes32[] eventLogHashes;
}

struct PcrValue384 {
    uint8 pcrIndex;
    Bytes48 value;
    Bytes48[] eventLogHashes;
}

/// @notice Bank-aware TPM Quote evidence.
struct TpmQuoteEvidence {
    /// @dev Bare marshalled TPMS_ATTEST with no TPM2B size prefix.
    bytes tpmsAttest;
    /// @dev Exact marshalled TPMT_SIGNATURE.
    bytes tpmSignature;
    /// @dev 0xff means no StartupLocality record; 0 through 4 are accepted localities.
    uint8 pcr0StartupLocality;
    PcrValue256[] pcrValues256;
    PcrValue384[] pcrValues384;
}

/// @notice Raw TPM Certify evidence.
struct TpmCertifyEvidence {
    bytes tpmsAttest;
    /// @dev Exact marshalled TPMT_SIGNATURE over tpmsAttest.
    bytes tpmSignature;
    /// @dev TPMT_PUBLIC structure of the certified key (attributes at offset 4)
    bytes tpmtPublic;
}

/// @notice Attestation Key public key collateral for AK authentication
struct AkPubCollateral {
    /// @dev Format of the collateral data.
    AkPubCollateralType akPubCollateralType;
    /// @dev Backend selected for this exact collateral format.
    VerificationBackendType verificationBackendType;
    /// @dev Polymorphic data field:
    ///      - AzureMaaJwt: abi.encode((bytes jwt, bytes hclVarData))
    ///      - GcpCertChain: X.509 certificate chain (DER-encoded, abi.encoded bytes[])
    bytes data;
}

/// @notice Complete attestation evidence bundle for session registration
struct AttestationEvidence {
    /// @dev TEE attestation report (TDX quote or SEV-SNP report)
    TeeReport teeReport;
    /// @dev One full Attestation Key used by collateral, Quote, and Certify verification.
    PublicIdentity akPub;
    /// @dev TPM Quote report for PCR measurements
    TpmReport tpmQuoteReport;
    /// @dev TPM Certify report for TPM signing key certification
    TpmReport tpmCertifyReport;
    /// @dev Attestation Key public key collateral
    AkPubCollateral akPubCollateral;
    /// @dev abi.encode(bytes tpmDelegationSignature, bytes sessionKeyPossessionSignature).
    ///      Both signatures cover keccak256(abi.encode(DELEGATION_DOMAIN, chainId,
    ///      sessionRegistry, baseImageId, workloadId, sessionId, sessionKeyFingerprint)).
    ///      The TPM signature binds the session key to the attested TPM. The session-key
    ///      signature proves that the registrant owns the private key for sessionKey.
    bytes sessionKeySignature;
    /// @dev Session public key (operational key for application use)
    PublicIdentity sessionKey;
}

/// @notice Evidence for cheap session-key rotation without fresh TEE verification.
struct SessionKeyRotationEvidence {
    TpmReport tpmQuoteReport;
    TpmReport tpmCertifyReport;
    /// @dev Same two-signature ABI encoding as AttestationEvidence.sessionKeySignature.
    bytes sessionKeySignature;
    PublicIdentity sessionKey;
    bytes rotationSignature;
    PublicIdentity oldTpmSigningKey;
    PublicIdentity akPub;
}

/// @notice Predecessor TPM authorization for a fully attested session renewal.
struct SessionRenewalAuthorization {
    bytes signature;
    PublicIdentity oldTpmSigningKey;
}
