// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {TEEType, CloudType, TeeReportType, Measurement} from "../lib/LibTEE.sol";
import {WorkloadCollaterals} from "./IWorkloadVerifier.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";

struct CVMConfig {
    TEEType teeType;
    CloudType cloudType;
    uint64 teeTTL;
    uint64 tpmTTL;
    uint64 teeRecentTimestamp;
    uint64 tpmRecentTimestamp;
    bytes32 measurementHash;
    bytes teeAttestationOutput;
    CertPubkey cvmIdentity;
    CertPubkey tpmAk;
}

interface ICVMRegistry {
    error CVM_NOT_REGISTERED();
    error CVM_IDENTITY_MISMATCH(bytes32 expected, bytes32 actual);
    error INVALID_SIGNATURE();
    error UNSUPPORTED_HASH_ALGORITHM(uint16 hashAlgo);
    error INVALID_TPM_DATA_LENGTH();
    error INVALID_TPM_QUOTE(string err);
    error INVALID_TPM_MEASUREMENT(string err);
    error TPM_AK_MISMATCH(bytes32 expected, bytes32 actual);
    error TEE_COLLATERAL_EXPIRED();
    error TPM_COLLATERAL_EXPIRED();

    event CVMUpdated(bytes32 indexed cvmIdentityHash);
    event CVMTTLUpdated(bytes32 indexed cvmIdentityHash);

    /// @notice Invoke this method to attest their CVM and
    ///         register the workload generated key as their onchain identity
    function attestCvm(
        CloudType cloudType,
        TEEType teeType,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external returns (Measurement memory measurements);

    /// @notice Call this method if:
    ///         (1) TPM report is stale, but TEE is still fresh.
    ///         (2) Users intend to rotate their identity keys
    /// @dev Must check TEE validity
    /// @dev Must verify signature against existing CVM identity
    /// @dev If wc contains the CVM identity key that does not match with
    ///      existing cvm identity, a key rotation occurs.
    /// @dev In this scenario, you must also check that TPM extraData
    ///      contains the new CVM identity hash.
    /// @dev The entire config will be re-mapped using the new CVM identity hash
    function reattestCvmWithTpm(bytes32 cvmIdentityHash, bytes calldata signature, WorkloadCollaterals calldata wc)
        external
        returns (Measurement memory measurements);

    /// @dev sig + TEE and TPM validity
    function setCollateralTTL(bytes32 cvmIdentityHash, uint64 teeTTL, uint64 tpmTTL, bytes calldata signature)
        external;

    /// ===== HELPER METHODS =====

    function nonces(bytes32 cvmIdentityHash) external view returns (uint256);

    function hasRegistered(bytes32 cvmIdentityHash) external view returns (bool);

    function checkTEEValidity(bytes32 cvmIdentityHash) external view returns (bool valid);

    function checkTPMValidity(bytes32 cvmIdentityHash) external view returns (bool valid);

    function getMeasurementHash(bytes32 cvmIdentityHash) external view returns (bytes32 hash);

    function getCvmIdentity(bytes32 cvmIdentityHash) external view returns (CertPubkey memory identity);

    /// @notice Use this method if you need to load everything
    ///         about the registered CVM
    function getCvmConfig(bytes32 cvmIdentityHash) external view returns (CVMConfig memory config);
}
