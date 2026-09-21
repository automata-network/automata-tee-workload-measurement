// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @notice Compact DCAP V2 ABI pinned to upstream 8be7030.
interface IDcapAttestationV2 {
    enum ZkCoProcessorType {
        None,
        RiscZero,
        Succinct,
        Pico
    }

    function verifyAndAttestOnChainV2(bytes calldata quote, uint32 tcbEvaluationDataNumber, bool minCheck)
        external
        payable
        returns (bool success, bytes memory output, bytes memory quoteBody);

    function verifyAndAttestWithZKProofV2(
        bytes calldata journal,
        ZkCoProcessorType backend,
        bytes calldata proof,
        bytes32 programIdentifier,
        uint32 tcbEvaluationDataNumber,
        bool minCheck
    ) external payable returns (bool success, bytes memory output);

    function programModeV2(ZkCoProcessorType backend, bytes32 programIdentifier)
        external
        view
        returns (bool registered, bool minCheck);
    function zkV2Paused() external view returns (bool);
    function zkVerifierV2(ZkCoProcessorType backend, bytes4 selector) external view returns (address);
}
