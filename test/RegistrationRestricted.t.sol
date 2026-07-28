// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";

contract RegistrationRestrictedTest is Test {
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;

    function setUp() public {
        MockSignatureVerifier signatureVerifier = new MockSignatureVerifier();

        BaseImageRegistry baseImplementation = new BaseImageRegistry(signatureVerifier);
        baseImageRegistry = BaseImageRegistry(
            address(
                new ERC1967Proxy(
                    address(baseImplementation), abi.encodeCall(BaseImageRegistry.initialize, (address(this)))
                )
            )
        );

        WorkloadRegistry workloadImplementation = new WorkloadRegistry(signatureVerifier);
        workloadRegistry = WorkloadRegistry(
            address(
                new ERC1967Proxy(
                    address(workloadImplementation), abi.encodeCall(WorkloadRegistry.initialize, (address(this)))
                )
            )
        );
    }

    function testRegistrationRestrictedNamesTheActualState() public {
        assertTrue(baseImageRegistry.registrationRestricted());
        assertTrue(workloadRegistry.registrationRestricted());

        baseImageRegistry.unpause();
        workloadRegistry.unpause();
        assertFalse(baseImageRegistry.registrationRestricted());
        assertFalse(workloadRegistry.registrationRestricted());

        baseImageRegistry.pause();
        workloadRegistry.pause();
        assertTrue(baseImageRegistry.registrationRestricted());
        assertTrue(workloadRegistry.registrationRestricted());
    }
}
