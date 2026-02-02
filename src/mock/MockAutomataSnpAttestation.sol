// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {ISnpAttestation, VerifierJournal} from "../interfaces/external/ISnpAttestation.sol";

/// @title MockAutomataDcapAttestation
contract MockAutomataSnpAttestation is ISnpAttestation {
    function verifyAndAttestWithZKProof(bytes calldata output, ZkCoProcessorType, bytes calldata)
        external
        pure
        returns (VerifierJournal memory verifiedOutput)
    {
        verifiedOutput = abi.decode(output, (VerifierJournal));
        return verifiedOutput;
    }
}
