//SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {WorkloadCollaterals} from "../lib/LibTPM.sol";
import {TEEType, TeeReportType, CloudType} from "../lib/LibTEE.sol";

interface IAttestationVerifier {
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

    function dcapAttestation() external view returns (address);
    function snpAttestation() external view returns (address);
    function certChainRegistryAddr() external view returns (address);
    function initialize(
        address _initialOwner,
        address _dcapAttestationAddr,
        address _snpAttestationAddr,
        address _certChainRegistry,
        bool _allowMockAttestation
    ) external;
    function version() external view returns (string memory);
    function owner() external view returns (address);
    function __constructor__() external;
}
