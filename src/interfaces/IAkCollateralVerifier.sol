// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {AkPubCollateral, AkPubCollateralType, TEEType} from "../types/Evidence.sol";
import {PcrCommitment, PublicIdentity} from "../types/Common.sol";

struct AkCollateralVerificationResult {
    bytes32 akPubFingerprint;
    TEEType teeType;
    bytes32 bindingHash;
    bytes32 amdSevSnpReportHash;
    bytes32 awsNitroRootCertHash;
    bytes32 qualifyingData;
    uint64 documentTimestampSeconds;
    PcrCommitment pcrCommitment;
}

interface IAkCollateralVerifier {
    function validateAkPub(AkPubCollateralType collateralType, PublicIdentity calldata akPub)
        external
        pure
        returns (bytes32 fingerprint);

    function verifyAkCollateral(AkPubCollateral calldata collateral)
        external
        returns (AkCollateralVerificationResult memory result);
}
