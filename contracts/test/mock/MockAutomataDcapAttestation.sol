//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IDcapAttestation} from "src/interfaces/IDcapAttestation.sol";

/// @title MockAutomataDcapAttestation
contract MockAutomataDcapAttestation is IDcapAttestation {
    struct Output {
        uint16 quoteVersion; // serialized as BE, for EVM compatibility
        bytes4 tee;
        uint8 tcbStatus;
        bytes6 fmspcBytes;
        bytes quoteBody;
        string[] advisoryIDs;
    }

    function getBp() external pure returns (uint16) {
        return 0;
    }

    function verifyAndAttestOnChain(bytes calldata input) external payable returns (bool, bytes memory) {
        bytes calldata rawBody = input[48:48 + 584];
        Output memory output = Output({
            quoteVersion: 4,
            tee: 0x81000000,
            tcbStatus: 1,
            fmspcBytes: bytes6(0),
            quoteBody: rawBody,
            advisoryIDs: new string[](0)
        });
        return (true, serializeOutput(output));
    }

    function verifyAndAttestWithZKProof(bytes calldata journal, ZkCoProcessorType, bytes calldata)
        external
        payable
        returns (bool success, bytes memory output)
    {
        return (true, journal);
    }

    function serializeOutput(Output memory output) internal pure returns (bytes memory) {
        return abi.encodePacked(
            output.quoteVersion,
            output.tee,
            output.tcbStatus,
            output.fmspcBytes,
            output.quoteBody,
            output.advisoryIDs.length > 0 ? abi.encode(output.advisoryIDs) : bytes("")
        );
    }
}
