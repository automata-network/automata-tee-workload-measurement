// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    PcrBankSelection,
    PcrPolicyBlock,
    PcrSpec256,
    PcrSpec384,
    Attribute,
    PublicIdentity
} from "../src/types/Common.sol";

/// @dev Reproduces the cross-parent getVariant bug:
///      `getVariant(baseImageId, platformProfileId, variantId)` previously
///      only checked each id existed in isolation. Two unrelated base images
///      could be combined into a single triple, returning unrelated PCR
///      policy data and (via SessionRegistry._lookupPolicy) letting an
///      attacker register a session with PCRs verified against a different
///      base image's policy.
contract BaseImageRegistryHierarchyTest is Test {
    uint8 constant ALGO_ID_ES256K = 0x02;

    address constant OWNER = address(0xA11CE);

    BaseImageRegistry internal registry;
    SignatureVerifier internal signatureVerifier;

    PublicIdentity internal ownerIdentity;
    bytes32 internal ownerFingerprint;

    error HierarchyMismatch(bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId);

    function setUp() public {
        // SignatureVerifier address is not exercised — registerBaseImage's sig check is mocked.
        signatureVerifier = new SignatureVerifier(address(0));

        BaseImageRegistry impl = new BaseImageRegistry(ISignatureVerifier(address(signatureVerifier)));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(BaseImageRegistry.initialize, (OWNER)));
        registry = BaseImageRegistry(address(proxy));

        ownerIdentity = PublicIdentity({typeId: ALGO_ID_ES256K, key: hex"0102030405060708090a0b0c0d0e0f"});
        ownerFingerprint = LibKey.computeKeyFingerprint(ownerIdentity);

        // Default-paused; whitelist our test fingerprint so registerBaseImage can proceed.
        vm.prank(OWNER);
        bytes32[] memory fps = new bytes32[](1);
        fps[0] = ownerFingerprint;
        registry.addToWhitelist(fps);

        // Bypass owner-signature verification.
        vm.mockCall(
            address(signatureVerifier), abi.encodeWithSelector(SignatureVerifier.verify.selector), abi.encode(true)
        );

        vm.warp(1_700_000_000);
    }

    function _register(string memory name, string memory ver, string memory profileName, string memory variantName)
        internal
        returns (bytes32 baseImageId, bytes32 platformProfileId, bytes32 variantId)
    {
        BaseImageSpec memory spec = BaseImageSpec({name: name, version: ver, uri: ""});

        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: profileName,
            pcrBankSelection: PcrBankSelection.Sha256,
            invariantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });

        MeasurementVariant[][] memory variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: variantName,
            variantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });

        baseImageId =
            registry.registerBaseImage(spec, profiles, variants, uint64(block.timestamp + 1000), ownerIdentity, "");

        bytes32[] memory profileIds = registry.getPlatformProfileIds(baseImageId);
        platformProfileId = profileIds[0];

        bytes32[] memory variantIds = registry.getMeasurementVariantIds(platformProfileId);
        variantId = variantIds[0];
    }

    // ─── Tests ──────────────────────────────────────────────────────────────

    function testGetVariant_AcceptsValidTriple() public {
        (bytes32 b, bytes32 p, bytes32 v) = _register("img-a", "v1", "gcp-tdx", "c3-standard-4");
        registry.getVariant(b, p, v); // must not revert
    }

    function testGetVariant_RejectsCrossedPlatformProfile() public {
        (bytes32 bA,,) = _register("img-a", "v1", "gcp-tdx", "c3-standard-4");
        (, bytes32 pB, bytes32 vB) = _register("img-b", "v1", "gcp-snp", "n2d-standard-2");

        // bA is real, pB+vB are real, but pB was registered under img-b, not img-a.
        vm.expectRevert(abi.encodeWithSelector(HierarchyMismatch.selector, bA, pB, vB));
        registry.getVariant(bA, pB, vB);
    }

    function testGetVariant_RejectsCrossedVariant() public {
        // Same base image, two different platform profiles, each with its own variant.
        BaseImageSpec memory spec = BaseImageSpec({name: "img-c", version: "v1", uri: ""});

        PlatformProfile[] memory profiles = new PlatformProfile[](2);
        profiles[0] = PlatformProfile({
            name: "gcp-tdx",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });
        profiles[1] = PlatformProfile({
            name: "gcp-snp",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });

        MeasurementVariant[][] memory variants = new MeasurementVariant[][](2);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: "tdx-var",
            variantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });
        variants[1] = new MeasurementVariant[](1);
        variants[1][0] = MeasurementVariant({
            name: "snp-var",
            variantPcrPolicy: PcrPolicyBlock({pcrSpecs256: new PcrSpec256[](0), pcrSpecs384: new PcrSpec384[](0)}),
            attributes: new Attribute[](0)
        });

        bytes32 baseImageId =
            registry.registerBaseImage(spec, profiles, variants, uint64(block.timestamp + 1000), ownerIdentity, "");

        bytes32[] memory profileIds = registry.getPlatformProfileIds(baseImageId);
        bytes32 pTdx = profileIds[0];
        bytes32 pSnp = profileIds[1];

        bytes32[] memory tdxVariants = registry.getMeasurementVariantIds(pTdx);
        bytes32[] memory snpVariants = registry.getMeasurementVariantIds(pSnp);
        bytes32 vTdx = tdxVariants[0];
        bytes32 vSnp = snpVariants[0];

        // (baseImageId, pTdx, vSnp): tdx profile, but snp's variant -> hierarchy mismatch.
        vm.expectRevert(abi.encodeWithSelector(HierarchyMismatch.selector, baseImageId, pTdx, vSnp));
        registry.getVariant(baseImageId, pTdx, vSnp);

        // Sanity: each profile with its own variant succeeds.
        registry.getVariant(baseImageId, pTdx, vTdx);
        registry.getVariant(baseImageId, pSnp, vSnp);
    }
}
