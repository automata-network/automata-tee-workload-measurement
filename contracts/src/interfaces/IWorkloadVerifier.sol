//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {
    ITpmAttestation, MeasureablePcr
} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {IDcapAttestation} from "./IDcapAttestation.sol";
import {ISnpAttestation} from "./ISnpAttestation.sol";
import {TEEType, TeeReportType, CloudType} from "../lib/LibTEE.sol";

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

interface IWorkloadVerifier {
    // b0c0fe51
    error INVALID_REPORT();
    // d0e356d5
    error INVALID_REPORT_DATA();
    // 8d35c978
    error MOCK_ATTESTATION_NOT_ALLOWED();
    // 0a6fdd83
    error TEE_REPORT_DATA_MISMATCH(bytes32 want, bytes32 got);
    // ddf0d9a4
    error INVALID_TEE_REPORT_TYPE(TeeReportType teeReportType);
    // 4536070c
    error INVALID_TEE_TYPE(TEEType teeType);
    // 0ccce91b
    error INVALID_CLOUD_TYPE(CloudType cloudType);

    /**
     * @dev Verifies the integrity of a CVM Workload
     * @param _userDataHash The hash of the user data.
     * @param teeType Intel TDX or AMD-SEV-SNP
     * @param teeReportType Solidity vs ZK TEE report types
     * @param cloudType indicates the cloud provider
     * @param _teeAttestationReport The TEE attestation report.
     * @param _workloadReport Additional data required for verification, such as TPM quote and PCRs.
     * @return The hash of the measured workload
     * @dev can provide their own golden measurement hash to be referenced for checking the integrity of the workload.
     */
    function verifyAttestation(
        bytes32 _userDataHash,
        TEEType teeType,
        TeeReportType teeReportType,
        CloudType cloudType,
        bytes calldata _teeAttestationReport,
        WorkloadCollaterals calldata _workloadReport
    ) external payable returns (bytes32);

    /**
     * @dev Estimates the fee for verifying the quote on-chain.
     * @param rawQuote The raw quote data.
     * @return The estimated fee.
     * @notice The actual fee is determined by multiplying the base fee with the gas price.
     */
    function estimateBaseFeeVerifyOnChain(bytes calldata rawQuote) external payable returns (uint256);

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
