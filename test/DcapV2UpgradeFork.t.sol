// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {UpgradeDcapV2} from "../script/UpgradeDcapV2.s.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {ZkProgramConfig, ZkProofType} from "../src/types/Zk.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";

contract DcapV2UpgradeForkTest is Test {
    function test_public_upgrade_preserves_existing_session_and_rollback() public {
        string memory rpc = vm.envOr("DCAP_V2_UPGRADE_TEST_RPC", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc);
        SessionRegistry session = SessionRegistry(vm.envAddress("SESSION_REGISTRY_ADDR"));
        bytes32 id = vm.envBytes32("EXISTING_SESSION_ID");
        bytes memory existing = abi.encode(session.getSession(id));
        bytes32 owner = session.getSessionOwner(id);
        require(owner != bytes32(0), "existing session required");
        address tee = address(session.teeVerifier());
        address tpm = address(session.tpmVerifier());
        address baseImage = address(session.baseImageRegistry());
        address workload = address(session.workloadRegistry());
        bytes32[50] memory slots;
        for (uint256 i; i < slots.length; i++) {
            slots[i] = vm.load(address(session), bytes32(i));
        }

        UpgradeDcapV2 upgrade = new UpgradeDcapV2();
        upgrade.run();
        assertTrue(address(session.teeVerifier()) != tee);
        assertEq(address(session.tpmVerifier()), tpm);
        assertEq(address(session.baseImageRegistry()), baseImage);
        assertEq(address(session.workloadRegistry()), workload);
        assertEq(abi.encode(session.getSession(id)), existing);
        assertEq(session.getSessionOwner(id), owner);
        for (uint256 i; i < slots.length; i++) {
            assertEq(vm.load(address(session), bytes32(i)), slots[i]);
        }

        ZkVerifierRegistry registry = ZkVerifierRegistry(address(TeeVerifier(tee).zkVerifierRegistry()));
        bytes32 v2Id = 0x00c8b2488a43ef337639997a56c160087126c97fec1667c0e2ecbe137688729f;
        ZkProgramConfig memory v2 =
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, v2Id);
        vm.startPrank(vm.envAddress("OWNER"));
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, v2Id, v2.verifierAdapter, false
        );
        session.upgradeToAndCall(vm.envAddress("EXPECTED_SESSION_IMPLEMENTATION"), "");
        vm.stopPrank();
        assertFalse(
            registry.getZkProgramConfig(ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, v2Id).enabled
        );
        assertEq(address(session.teeVerifier()), tee);
        assertEq(abi.encode(session.getSession(id)), existing);
        assertEq(session.getSessionOwner(id), owner);
        for (uint256 i; i < slots.length; i++) {
            assertEq(vm.load(address(session), bytes32(i)), slots[i]);
        }
    }
}
