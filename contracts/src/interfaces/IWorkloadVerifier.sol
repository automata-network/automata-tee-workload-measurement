//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {
    ITpmAttestation, MeasureablePcr
} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {Pubkey} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";

import {IDcapAttestation} from "./IDcapAttestation.sol";
import {ISnpAttestation} from "./ISnpAttestation.sol";
import {TEEType, TeeReportType, CloudType, Measurement, TEEVerifiedData} from "../lib/LibTEE.sol";

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
    // The CVM Identity
    Pubkey cvmIdentity;
}

interface IWorkloadVerifier {
    // 8d35c978
    error MOCK_ATTESTATION_NOT_ALLOWED();
    // ddf0d9a4
    error INVALID_TEE_REPORT_TYPE(TeeReportType teeReportType);
    // 4536070c
    error INVALID_TEE_TYPE(TEEType teeType);
    // 0ccce91b
    error INVALID_CLOUD_TYPE(CloudType cloudType);
    // 8512b796
    error FAILED_TO_VERIFY_TEE();
    // 2a2eafda
    error INVALID_TEE_REPORT();
    // 0a6fdd83
    error TEE_REPORT_DATA_MISMATCH(bytes32 want, bytes32 got);
    // 70c6a010
    error FAILED_TO_VERIFY_TPM_QUOTE(string errorMessage);
    // c5ee0cd0
    error FAILED_TO_CHECK_PCR_MEASUREMENTS(string errorMessage);

    /**
     * @notice Call this method if you are interested in getting TEE-verified data
     * such as: Report ID, TPM AK Pubkey and TEE Measurements
     * @param teeType Intel TDX or AMD-SEV-SNP
     * @param teeReportType Solidity vs ZK TEE report types
     * @param cloudType indicates the cloud provider
     * @param _teeAttestationReport The TEE attestation report.
     * @param _workloadReport Additional data required for verification, such as TPM quote and PCRs.
     * @return teeOutput the output obtained from the TEE Verifier contract
     * @return teeVerifiedData data that have been verified by the TEE, and can be trusted
     * @return tpmExtraData additional data extracted from the TPM quote
     */
    function verifyAttestation(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _workloadReport
    )
        external
        payable
        returns (bytes memory teeOutput, TEEVerifiedData memory teeVerifiedData, bytes memory tpmExtraData);

    /**
     * @notice Call this method if you are only interested in getting the Workload Measurement
     * @param teeType Intel TDX or AMD-SEV-SNP
     * @param teeReportType Solidity vs ZK TEE report types
     * @param cloudType indicates the cloud provider
     * @param _teeAttestationReport The TEE attestation report.
     * @param _workloadReport Additional data required for verification, such as TPM quote and PCRs.
     * @return teeOutput the output obtained from the TEE Verifier contract
     * @return measurement the Final Measurement
     * @return tpmExtraData additional data extracted from the TPM quote
     */
    function verifyAttestationAndGetMeasurement(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _workloadReport
    ) external payable returns (bytes memory teeOutput, Measurement memory measurement, bytes memory tpmExtraData);

    /**
     * @notice Call this method if you are only interested in getting the hash of the Workload Measurement
     * @param teeType Intel TDX or AMD-SEV-SNP
     * @param teeReportType Solidity vs ZK TEE report types
     * @param cloudType indicates the cloud provider
     * @param _teeAttestationReport The TEE attestation report.
     * @param _workloadReport Additional data required for verification, such as TPM quote and PCRs.
     * @return teeOutput the output obtained from the TEE Verifier contract
     * @return measurementHash the hash of the Final Measurement
     * @return tpmExtraData additional data extracted from the TPM quote
     * @dev can provide their own golden measurement hash to be referenced for checking the integrity of the workload.
     */
    function verifyAttestationAndGetMeasurementHash(
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _workloadReport
    ) external payable returns (bytes memory teeOutput, bytes32 measurementHash, bytes memory tpmExtraData);

    /**
     * @notice Helper Method to parse raw TEE output
     */
    function parseTeeOutput(TEEType teeType, bytes memory teeOutput) external pure returns (TEEVerifiedData memory);

    /**
     * @notice Get the Final Measurement from the TEE Verified Data and measured PCRs
     */
    function getMeasurement(TEEVerifiedData memory teeVerifiedData, MeasureablePcr[] memory pcrs)
        external
        view
        returns (Measurement memory);

    /**
     * @notice Helper method to parse the varKey json string to extract the AK public key
     */
    function parseVarKeyJson(string calldata varKey) external pure returns (Pubkey memory akPub);

    /**
     * @return The DcapAttestation interface for verifying Intel DCAP Quotes
     */
    function dcapAttestation() external view returns (IDcapAttestation);
    /**
     * @return The SnpAttestation interface for verifying AMD SEV-SNP Attestations
     */
    function snpAttestation() external view returns (ISnpAttestation);
    /**
     * @return The TpmAttestation interface for verifying TPM Quotes
     */
    function tpmAttestation() external view returns (ITpmAttestation);
    /**
     * @return True if mock attestation is allowed, false otherwise.
     */
    function allowMockAttestation() external view returns (bool);
}
