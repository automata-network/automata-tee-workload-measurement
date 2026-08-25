// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";

contract TpmVerifierV2 is TpmVerifier {
    constructor(ITpmAttestation tpmAttestation, IZkVerifierRegistry zkVerifierRegistry)
        TpmVerifier(tpmAttestation, zkVerifierRegistry)
    {}

    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract TpmVerifierUpgradeTest is Test {
    address private constant TPM_ATTESTATION = address(0x1001);
    address private constant ZK_VERIFIER_REGISTRY = address(0x1002);
    address private constant OWNER = address(0x1003);
    address private constant UNAUTHORIZED = address(0x1004);

    TpmVerifier private verifier;

    function setUp() public {
        TpmVerifier implementation =
            new TpmVerifier(ITpmAttestation(TPM_ATTESTATION), IZkVerifierRegistry(ZK_VERIFIER_REGISTRY));
        verifier = TpmVerifier(
            address(new ERC1967Proxy(address(implementation), abi.encodeCall(TpmVerifier.initialize, (OWNER))))
        );
    }

    function testOwnerCanUpgradeWithoutChangingSessionRegistryTpmVerifierAddress() public {
        address proxyAddress = address(verifier);
        TpmVerifierV2 nextImplementation =
            new TpmVerifierV2(ITpmAttestation(TPM_ATTESTATION), IZkVerifierRegistry(ZK_VERIFIER_REGISTRY));

        vm.prank(OWNER);
        verifier.upgradeToAndCall(address(nextImplementation), "");

        assertEq(address(verifier), proxyAddress);
        assertEq(TpmVerifierV2(address(verifier)).implementationVersion(), 2);
        assertEq(address(verifier.tpmAttestation()), TPM_ATTESTATION);
        assertEq(address(verifier.zkVerifierRegistry()), ZK_VERIFIER_REGISTRY);
    }

    function testNonOwnerCannotUpgrade() public {
        TpmVerifierV2 nextImplementation =
            new TpmVerifierV2(ITpmAttestation(TPM_ATTESTATION), IZkVerifierRegistry(ZK_VERIFIER_REGISTRY));

        vm.prank(UNAUTHORIZED);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", UNAUTHORIZED));
        verifier.upgradeToAndCall(address(nextImplementation), "");
    }
}
