// SPDX-License-Identifier: MIT
// Automata Contracts
pragma solidity ^0.8.0;

import {TEEType, CloudType, TeeReportType, Measurement} from "../lib/LibTEE.sol";
import {WorkloadCollaterals} from "./IWorkloadVerifier.sol";
import {Pubkey} from "@automata-network/automata-tpm-attestation/types/Crypto.sol";

struct CVMConfig {
    TEEType teeType;
    CloudType cloudType;
    uint64 teeTTL;
    uint64 tpmTTL;
    uint64 teeRecentTimestamp;
    uint64 tpmRecentTimestamp;
    bytes32 measurementHash;
    Pubkey cvmIdentity;
    bytes teeAttestationOutput;
}

interface ICVMRegistry {
    error CVM_NOT_REGISTERED();
    error CVM_REGISTERED(bytes32 cvmIdentityHash);
    error CVM_IDENTITY_MISMATCH(bytes32 expected, bytes32 actual);
    error INVALID_SIGNATURE();
    error UNSUPPORTED_HASH_ALGORITHM(uint16 hashAlgo);
    error INVALID_TPM_QUOTE(string err);
    error INVALID_TPM_MEASUREMENT(string err);

    event CVMRegistered(bytes32 indexed cvmIdentityHash);
    event CVMIdentityRotated(bytes32 indexed newIdentityHash, bytes32 oldIdentityHash);
    event CVMCollateralUpdated(bytes32 indexed cvmIdentityHash, uint64 teeTimestamp, uint64 tpmTimestamp);
    event CVMTTLUpdated(bytes32 indexed cvmIdentityHash, uint64 teeTTL, uint64 tpmTTL);

    /**
     * @notice new-users invoke this method to attest their CVM and
     * register the workload generated key as their onchain identity
     */
    function registerCvm(
        CloudType cloudType,
        TEEType teeType,
        TeeReportType teeReportType,
        bytes calldata teeAttestationReport,
        WorkloadCollaterals calldata wc
    ) external returns (Measurement memory measurements);

    /**
     * @notice call this method if:
     * (1) TPM report is stale, but TEE is still fresh.
     * (2) Users intend to rotate their identity keys
     *
     * @dev must check TEE validity
     * @dev must verify signature against existing CVM identity
     *
     * @dev if wc contains the CVM identity key that does not match with
     * existing cvm identity, a key rotation occurs.
     * @dev in this scenario, you must also check that TPM extraData
     * contains the new CVM identity hash.
     * @dev the entire config will be re-mapped using the new CVM identity hash
     */
    function reattestCvmWithTpm(bytes32 cvmIdentityHash, bytes calldata signature, WorkloadCollaterals calldata wc)
        external
        returns (Measurement memory measurements);

    /**
     * @notice this is a more "extreme" version of
     * the reattestCvmWithTpm method
     * because it also re-attests the TEE component of the workload
     *
     * @notice users must call this method
     * if the submitted TEE report has gone stale
     *
     * @dev must verify signature against CVM identity
     * @dev key-rotation is also possible here
     */
    function reattestCvmFully(
        bytes32 cvmIdentityHash,
        TeeReportType teeReportType,
        bytes calldata signature,
        bytes calldata teeReport,
        WorkloadCollaterals calldata wc
    ) external returns (Measurement memory measurements);

    /**
     * @dev sig + TEE and TPM validity
     */
    function setCollateralTTL(bytes32 cvmIdentityHash, uint64 teeTTL, uint64 tpmTTL, bytes calldata signature)
        external;

    /// ===== HELPER METHODS =====

    function nonces(bytes32 cvmIdentityHash) external view returns (uint256);

    function checkTEEValidity(bytes32 cvmIdentityHash) external view returns (bool valid);

    function checkTPMValidity(bytes32 cvmIdentityHash) external view returns (bool valid);

    function getMeasurementHash(bytes32 cvmIdentityHash) external view returns (bytes32 hash);

    function getCvmIdentity(bytes32 cvmIdentityHash) external view returns (Pubkey memory identity);

    /// @notice use this method if you need to load everything
    /// about the registered CVM
    function getCvmConfig(bytes32 cvmIdentityHash) external view returns (CVMConfig memory config);
}
