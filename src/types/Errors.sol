// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TEEType} from "./Evidence.sol";

// General errors
/// @notice Thrown when attempting to register a session that already exists
error SessionAlreadyRegistered(bytes32 sessionId);
/// @notice Thrown when querying a session that does not exist
error SessionNotFound(bytes32 sessionId);
/// @notice Thrown when caller lacks permission for the requested operation
error Unauthorized();
/// @notice Thrown when attempting to use a session that has expired
error SessionExpired(bytes32 sessionId);
/// @notice Thrown when attempting to revoke a session that is already revoked
error SessionAlreadyRevoked(bytes32 sessionId);
/// @notice Thrown when a function parameter is invalid or out of bounds
error InvalidParameter(string paramName);

// TEE Report Validation errors
/// @notice Thrown when TEE attestation report verification fails
error TEEVerificationFailed(string reason);
/// @notice Thrown when TEE report data cannot be parsed or is malformed
error InvalidTEEReportFormat();
/// @notice Thrown when TEE report signature verification fails
error TEESignatureInvalid();
/// @notice Thrown when the TEE type is not supported by the verifier
error UnsupportedTEEType(TEEType teeType);

// Attestation Keys Validation errors
/// @notice Thrown when Attestation Key public key authentication fails (e.g., cloud provider signature invalid)
error AKPubAuthenticationFailed(string reason);
/// @notice Thrown when extracted AK public key hash does not match TEE report binding
error AKPubHashMismatch();
/// @notice Thrown when X.509 certificate chain validation fails (GCP vTPM endorsement)
error CertificateChainInvalid();
/// @notice Thrown when AK public key cannot be extracted from collateral
error AKPubExtractionFailed();

// TPM Quote Validation errors
/// @notice Thrown when TPM Quote signature verification fails (using AK public key)
error TPMQuoteSignatureInvalid();
/// @notice Thrown when TPM Quote data structure cannot be parsed (malformed TPM2B_ATTEST)
error TPMQuoteParsingFailed();
/// @notice Thrown when TPM Quote nonce does not match expected session nonce
error TPMNonceMismatch();

// TPM-TEE Binding errors
/// @notice Thrown when TPM and TEE binding verification fails (vTPM not anchored to TEE instance)
error TPMTEEBindingFailed(string reason);
/// @notice Thrown when vTPM UUID does not match TEE report UUID (Azure binding check)
error UUIDMismatch();
/// @notice Thrown when report ID binding check fails (GCP binding check)
error ReportIDMismatch();

// TPM Signing Key Certification Validation Errors
/// @notice Thrown when TPM signing key cannot be found in TPM Certify report
error TPMSigningKeyNotFound();
/// @notice Thrown when TPM signing key certification validation fails (invalid TPM2_Certify)
error TPMSigningKeyInvalid();

// Platform Policy Validation Errors
/// @notice Thrown when the specified platform profile does not exist in the base image registry
error PlatformProfileNotFound(bytes32 platformProfileId);
/// @notice Thrown when platform policy requirements are not met (e.g., attribute mismatch)
error PlatformPolicyViolation(string reason);

// Base Image Measurement Validation Errors
/// @notice Thrown when base image PCR measurement verification fails
error BaseImageMeasurementFailed(string reason);
/// @notice Thrown when the specified base image does not exist in the registry
error BaseImageNotFound(bytes32 baseImageId);
/// @notice Thrown when attempting to use a deactivated base image
error BaseImageInactive(bytes32 baseImageId);
/// @notice Thrown when base image PCR value does not match expected value
error BaseImagePCRMismatch(uint256 pcrIndex, bytes32 expected, bytes32 actual);
/// @notice Thrown when a required PCR is missing from the TPM Quote
error MissingRequiredPCR(uint256 pcrIndex);
/// @notice Thrown when the specified measurement variant does not exist for the base image profile
error MeasurementVariantNotFound(bytes32 variantKey);

// Workload Measurement Validation Errors
/// @notice Thrown when workload PCR measurement verification fails
error WorkloadMeasurementFailed(string reason);
/// @notice Thrown when the specified workload does not exist in the registry
error WorkloadNotFound(bytes32 workloadId);
/// @notice Thrown when attempting to use a deactivated workload
error WorkloadInactive(bytes32 workloadId);
/// @notice Thrown when the base image is not allowed by the workload policy (blacklist/whitelist violation)
error BaseImageNotAllowed(bytes32 baseImageId);
/// @notice Thrown when a workload attribute requirement is not satisfied
error WorkloadAttributeRequirementNotMet(bytes32 attributeKey);
/// @notice Thrown when workload PCR value does not match expected value
error WorkloadPCRMismatch(uint256 pcrIndex, bytes32 expected, bytes32 actual);

// Session Key Validation Errors
/// @notice Thrown when session key delegation chain validation fails
error SessionKeyDelegationFailed();
/// @notice Thrown when session key delegation signature verification fails (TPM signing key → session key)
error SessionKeyDelegationSignatureInvalid();
/// @notice Thrown when computed session key fingerprint does not match expected fingerprint
error SessionKeyFingerprintMismatch();
