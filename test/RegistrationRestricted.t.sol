// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {
    Attribute,
    BaseImageSpec,
    MeasurementVariant,
    PcrSpec,
    PlatformProfile,
    PublicIdentity
} from "../src/types/Common.sol";
import {TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, TEE_ATTRIBUTE_TRUE} from "../src/types/Constants.sol";

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

    /// @dev Appending a variant publishes a new selectable policy branch that may declare its own
    ///      reserved TEE attributes, so it is gated exactly like a fresh registration. An owner
    ///      removed from the whitelist must not be able to widen a base image they already own.
    function testAddPlatformVariantsIsWhitelistGated() public {
        PublicIdentity memory imageOwner = PublicIdentity({typeId: 2, key: hex"1234"});
        bytes32 fingerprint = LibKey.computeKeyFingerprint(imageOwner);

        bytes32[] memory whitelist = new bytes32[](1);
        whitelist[0] = fingerprint;
        baseImageRegistry.addToWhitelist(whitelist);

        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0].name = "azure-snp";
        profiles[0].invariants = new PcrSpec[](0);
        profiles[0].attributes = new Attribute[](0);

        MeasurementVariant[][] memory noVariants = new MeasurementVariant[][](1);
        noVariants[0] = new MeasurementVariant[](0);

        uint64 opExpiresAt = uint64(block.timestamp + 1 days);
        bytes32 baseImageId = baseImageRegistry.registerBaseImage(
            BaseImageSpec({name: "img", version: "1.0.0", uri: "ipfs://x"}),
            profiles,
            noVariants,
            opExpiresAt,
            imageOwner,
            hex"00"
        );

        baseImageRegistry.removeFromWhitelist(fingerprint);

        MeasurementVariant[][] memory newVariants = new MeasurementVariant[][](1);
        newVariants[0] = new MeasurementVariant[](1);
        newVariants[0][0].name = "debug-variant";
        newVariants[0][0].overridePcrs = new PcrSpec[](0);
        newVariants[0][0].attributes = new Attribute[](1);
        newVariants[0][0].attributes[0] = Attribute({key: TEE_ATTRIBUTE_AMD_SEV_SNP_DEBUG, value: TEE_ATTRIBUTE_TRUE});

        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.NotWhitelisted.selector, fingerprint));
        baseImageRegistry.addPlatformVariants(baseImageId, profiles, newVariants, opExpiresAt, imageOwner, hex"00");

        // Re-whitelisting, or lifting the restriction entirely, restores the update path.
        baseImageRegistry.unpause();
        baseImageRegistry.addPlatformVariants(baseImageId, profiles, newVariants, opExpiresAt, imageOwner, hex"00");
    }
}
