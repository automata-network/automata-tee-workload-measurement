// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {IAkCollateralVerifier} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {Bytes48} from "../src/lib/LibBytes.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    MeasurementVariant,
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    PcrVerifyType,
    PlatformProfile,
    PublicIdentity,
    ResolvedPcrPolicy,
    WorkloadSpec
} from "../src/types/Common.sol";

contract SelectablePcrPolicyTest is Test {
    address internal constant OWNER = address(0xa11ce);

    BaseImageRegistry internal baseImageRegistry;
    WorkloadRegistry internal workloadRegistry;
    SessionRegistry internal sessionRegistry;
    PublicIdentity internal publisher;

    function setUp() public {
        MockSignatureVerifier signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = BaseImageRegistry(
            address(
                new ERC1967Proxy(
                    address(new BaseImageRegistry(ISignatureVerifier(address(signatureVerifier)))),
                    abi.encodeCall(BaseImageRegistry.initialize, (OWNER))
                )
            )
        );
        workloadRegistry = WorkloadRegistry(
            address(
                new ERC1967Proxy(
                    address(new WorkloadRegistry(ISignatureVerifier(address(signatureVerifier)))),
                    abi.encodeCall(WorkloadRegistry.initialize, (OWNER))
                )
            )
        );
        sessionRegistry = SessionRegistry(
            address(
                new ERC1967Proxy(
                    address(
                        new SessionRegistry(
                            ITeeVerifier(address(1)),
                            TpmVerifier(address(2)),
                            ISignatureVerifier(address(signatureVerifier)),
                            IAkCollateralVerifier(address(4)),
                            baseImageRegistry,
                            workloadRegistry,
                            IAmdSnpSecurityPolicyRegistry(address(5))
                        )
                    ),
                    abi.encodeCall(SessionRegistry.initialize, (OWNER))
                )
            )
        );

        publisher = PublicIdentity({typeId: 3, key: hex"010203"});
        bytes32[] memory fingerprints = new bytes32[](1);
        fingerprints[0] = LibKey.computeKeyFingerprint(publisher);
        vm.startPrank(OWNER);
        baseImageRegistry.addToWhitelist(fingerprints);
        workloadRegistry.addToWhitelist(fingerprints);
        vm.stopPrank();
        vm.warp(1_800_000_000);
    }

    function testGetPcrPolicyReturnsBothBanksAndExactHierarchyIdentifiers() public {
        PcrSpec256[] memory invariants256 = new PcrSpec256[](1);
        invariants256[0] = _pcr256(0, bytes32(uint256(0x100)));
        PcrSpec384[] memory invariants384 = new PcrSpec384[](1);
        invariants384[0] = _pcr384(0, _bytes48(0x200, 0x201));

        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "aws-nitrotpm",
            pcrBankSelection: PcrBankSelection.Sha256AndSha384,
            invariants256: invariants256,
            invariants384: invariants384,
            attributes: new Attribute[](0)
        });

        PcrSpec256[] memory variantPcrs256 = new PcrSpec256[](1);
        variantPcrs256[0] = _pcr256(1, bytes32(uint256(0x300)));
        PcrSpec384[] memory variantPcrs384 = new PcrSpec384[](1);
        variantPcrs384[0] = _pcr384(1, _bytes48(0x400, 0x401));
        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: "m7i.large",
            variantPcrs256: variantPcrs256,
            variantPcrs384: variantPcrs384,
            attributes: new Attribute[](0)
        });

        bytes32 baseImageId = baseImageRegistry.registerBaseImage(
            BaseImageSpec({name: "base", version: "1", uri: ""}),
            profiles,
            variants,
            uint64(block.timestamp + 1 hours),
            publisher,
            ""
        );
        bytes32 platformProfileId = baseImageRegistry.getPlatformProfileIds(baseImageId)[0];
        bytes32 measurementVariantId = baseImageRegistry.getMeasurementVariantIds(platformProfileId)[0];

        PcrSpec256[] memory workloadPcrs256 = new PcrSpec256[](1);
        workloadPcrs256[0] = _pcr256(23, bytes32(uint256(0x500)));
        PcrSpec384[] memory workloadPcrs384 = new PcrSpec384[](1);
        workloadPcrs384[0] = _pcr384(23, _bytes48(0x600, 0x601));
        bytes32 workloadId = workloadRegistry.registerWorkload(
            WorkloadSpec({
                name: "workload",
                version: "1",
                sessionTtl: 1 days,
                baseImageMode: AccessMode.ANY,
                baseImageIds: new bytes32[](0),
                requirements: new AttributeRequirement[](0),
                workloadPcrs256: workloadPcrs256,
                workloadPcrs384: workloadPcrs384
            }),
            uint64(block.timestamp + 1 hours),
            publisher,
            ""
        );

        ResolvedPcrPolicy memory policy =
            sessionRegistry.getPcrPolicy(workloadId, baseImageId, platformProfileId, measurementVariantId);
        assertEq(policy.workloadId, workloadId);
        assertEq(policy.baseImageId, baseImageId);
        assertEq(policy.platformProfileId, platformProfileId);
        assertEq(policy.measurementVariantId, measurementVariantId);
        assertEq(uint8(policy.pcrBankSelection), uint8(PcrBankSelection.Sha256AndSha384));
        assertEq(policy.invariants256[0].matchData[0], bytes32(uint256(0x100)));
        assertEq(policy.variantPcrs256[0].matchData[0], bytes32(uint256(0x300)));
        assertEq(policy.workloadPcrs256[0].matchData[0], bytes32(uint256(0x500)));
        assertEq(policy.invariants384[0].matchData[0].first, bytes32(uint256(0x200)));
        assertEq(policy.variantPcrs384[0].matchData[0].first, bytes32(uint256(0x400)));
        assertEq(policy.workloadPcrs384[0].matchData[0].first, bytes32(uint256(0x600)));
    }

    function _pcr256(uint8 index, bytes32 value) private pure returns (PcrSpec256 memory rule) {
        bytes32[] memory matchData = new bytes32[](1);
        matchData[0] = value;
        return PcrSpec256({pcrIndex: index, verifyType: PcrVerifyType.STATIC, matchData: matchData});
    }

    function _pcr384(uint8 index, Bytes48 memory value) private pure returns (PcrSpec384 memory rule) {
        Bytes48[] memory matchData = new Bytes48[](1);
        matchData[0] = value;
        return PcrSpec384({pcrIndex: index, verifyType: PcrVerifyType.STATIC, matchData: matchData});
    }

    function _bytes48(uint256 first, uint128 second) private pure returns (Bytes48 memory) {
        return Bytes48({first: bytes32(first), second: bytes16(second)});
    }
}
