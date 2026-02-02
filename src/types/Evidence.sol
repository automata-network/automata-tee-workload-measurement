// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PcrValue, PublicIdentity} from "./Common.sol";

/// @notice Cloud provider classification for attestation routing
enum CloudType {
    /// @dev Microsoft Azure Confidential VMs
    Azure,
    /// @dev Google Cloud Confidential VMs
    GCP,
    /// @dev Amazon Web Services Nitro Enclaves
    AWS
}

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
    /// @dev Zero-knowledge proof via Succinct SP1
    ZkSuccinct,
    /// @dev Zero-knowledge proof via RISC Zero
    ZkRiscZero
}

/// @notice TPM report format for platform binding verification
enum TpmReportType {
    /// @dev TPM2_Quote — signed PCR snapshot with nonce binding
    TpmQuote,
    /// @dev TPM2_Certify — signed certification of a loaded key
    TpmCertify
}

/// @notice Generic zero-knowledge proof container
/// @dev Used by TeeReport.data and TpmReport.data when verification backend is ZK
struct ZkProof {
    /// @dev Public outputs (journal/public values) - visible on-chain
    bytes output;
    /// @dev Cryptographic proof blob (SNARK/STARK proof bytes)
    bytes proofBytes;
}

/// @notice Attestation Key (AK) public key collateral format
enum AkPubCollateralType {
    /// @dev Azure: JSON-encoded AK public key from vTPM
    AzureAkPubJson,
    /// @dev GCP: X.509 certificate chain from vTPM endorsement
    GcpCertChain
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

/// @notice TPM report for platform binding verification
struct TpmReport {
    /// @dev Verification backend (currently only Solidity supported; ZK support planned for event matching)
    VerificationBackendType verificationBackendType;
    /// @dev TPM report format (Quote or Certify)
    TpmReportType tpmReportType;
    /// @dev Polymorphic data field:
    ///      - Solidity: TpmQuoteReport or TpmCertifyReport
    ///      - ZkSuccinct: SP1 ZK proof (future)
    ///      - ZkRiscZero: RISC Zero ZK proof (future)
    bytes data;
}

/// @notice TPM Quote report containing PCR measurements and signature
struct TpmQuoteReport {
    /// @dev TPM2B_ATTEST structure (TPM 2.0 spec Part 2, Section 10.12.8)
    bytes tpm2bAttest;
    /// @dev TPMT_SIGNATURE structure over tpm2bAttest (TPM 2.0 spec Part 2, Section 11.2.3)
    bytes tpmSignature;
    /// @dev Decoded PCR values with event replay logs (for DYNAMIC verification)
    PcrValue[] pcrValues;
}

/// @notice TPM Certify report for key certification
struct TpmCertifyReport {
    /// @dev TPM2B_ATTEST structure for TPM2_Certify command
    bytes tpm2bAttest;
    /// @dev TPMT_SIGNATURE structure over tpm2bAttest
    bytes tpmSignature;
    /// @dev TPM2B_PUBLIC structure of the certified key
    bytes tpmtPublic;
}

/// @notice Attestation Key public key collateral for AK authentication
struct AkPubCollateral {
    /// @dev Format of the collateral data (Azure JSON or GCP cert chain)
    AkPubCollateralType akPubCollateralType;
    /// @dev Polymorphic data field:
    ///      - AzureAkPubJson: JSON-encoded AK public key
    ///      - GcpCertChain: X.509 certificate chain (DER-encoded)
    bytes data;
}

/// @notice Complete attestation evidence bundle for session registration
struct AttestationEvidence {
    /// @dev TEE attestation report (TDX quote or SEV-SNP report)
    TeeReport teeReport;
    /// @dev TPM Quote report for PCR measurements
    TpmReport tpmQuoteReport;
    /// @dev TPM Certify report for TPM signing key certification
    TpmReport tpmCertifyReport;
    /// @dev Attestation Key public key collateral
    AkPubCollateral akPubCollateral;
    /// @dev Delegation signature: tpmSigningKey signs sessionKey fingerprint
    bytes sessionKeySignature;
    /// @dev Session public key (operational key for application use)
    PublicIdentity sessionKey;
}
