//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {IDcapAttestation} from "./IDcapAttestation.sol";
import {ISnpAttestation} from "./ISnpAttestation.sol";
import {ITpmAttestation} from "./ITpmAttestation.sol";
import {MeasureablePcr} from "./ITpmAttestation.sol";
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

/// PCR Golden Measurement
struct Pcr {
    // pcr index
    uint256 index;
    // sanity check: require(pcr!=0 || measureEvents.length>0)
    // set to zero if no need to measure the pcr value
    bytes32 pcr;
    // the events wants to measure
    bytes32[] measureEvents;
    uint256[] measureEventsIdx;
}

interface IWorkloadVerifier {
    error INVALID_REPORT();
    error INVALID_REPORT_DATA();
    error MOCK_ATTESTATION_NOT_ALLOWED();
    error REPORT_DATA_MISMATCH(bytes32 want, bytes32 got);
    error INVALID_TEE_REPORT_TYPE(TeeReportType teeReportType);
    error INVALID_TEE_TYPE(TEEType teeType);
    error INVALID_CLOUD_TYPE(CloudType cloudType);

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

    function dcapAttestation() external view returns (IDcapAttestation);
    function snpAttestation() external view returns (ISnpAttestation);
    function tpmAttestation() external view returns (ITpmAttestation);
    function allowMockAttestation() external view returns (bool);
}
