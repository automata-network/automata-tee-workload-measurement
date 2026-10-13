// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PlatformProfile, MeasurementVariant, WorkloadSpec} from "../types/Common.sol";
import {BASEIMAGE_VARIANT_SIGNATURE_DOMAIN, WORKLOAD_POLICY_SIGNATURE_DOMAIN} from "../types/Constants.sol";

/// @notice Durable policy digests. No publication chain, registry, or expiry is included.
/// @dev IDs bind the publisher. Full parent profile bytes bind invariants, bank, and attributes.
library PublisherPolicy {
    function variantDigest(bytes32 baseImageId, PlatformProfile memory profile, MeasurementVariant memory variant)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encode(BASEIMAGE_VARIANT_SIGNATURE_DOMAIN, baseImageId, profile, variant));
    }

    function workloadDigest(bytes32 workloadId, WorkloadSpec memory spec) internal pure returns (bytes32) {
        return sha256(abi.encode(WORKLOAD_POLICY_SIGNATURE_DOMAIN, workloadId, spec));
    }
}
