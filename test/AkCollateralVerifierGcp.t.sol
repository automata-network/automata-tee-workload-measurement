// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TpmAttestation} from "@automata-network/automata-tpm-attestation/TpmAttestation.sol";
import {LibX509Verify} from "@automata-network/automata-tpm-attestation/lib/LibX509Verify.sol";
import {LeafCertIsCa, CertificateAlreadyRevoked} from "@automata-network/automata-tpm-attestation/types/Errors.sol";
import {AkCollateralVerifier} from "../src/bases/AkCollateralVerifier.sol";
import {AkPubCollateral, AkPubCollateralType, VerificationBackendType} from "../src/types/Evidence.sol";
import {IMaaKeyRegistry} from "../src/interfaces/registries/IMaaKeyRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";

contract AkCollateralVerifierGcpTest is Test {
    using stdJson for string;
    TpmAttestation internal tpm;
    AkCollateralVerifier internal verifier;
    string internal fixtures;

    function setUp() public {
        fixtures = vm.readFile("lib/automata-tpm-attestation/test/testdata/crl-authentication.json");
        vm.warp(1790251200);
        tpm = new TpmAttestation(address(this), LibX509Verify.P256_VERIFIER);
        tpm.addCA(fixtures.readBytes(".root"));
        verifier = new AkCollateralVerifier(
            IMaaKeyRegistry(address(0)), ISignatureVerifier(address(0)), tpm, IZkVerifierRegistry(address(0))
        );
    }

    function collateral(string memory target) internal view returns (AkPubCollateral memory) {
        bytes[] memory certs = new bytes[](2);
        certs[0] = fixtures.readBytes(string.concat(".", target));
        certs[1] = fixtures.readBytes(".root");
        return AkPubCollateral(AkPubCollateralType.GcpCertChain, VerificationBackendType.Solidity, abi.encode(certs));
    }

    function test_acceptsEndEntityAttestationCertificate() public {
        assertNotEq(verifier.verifyAkCollateral(collateral("leaf")).akPubFingerprint, bytes32(0));
    }

    function test_rejectsIntermediateAsAttestationKey() public {
        AkPubCollateral memory input = collateral("intermediate");
        vm.expectRevert(LeafCertIsCa.selector);
        verifier.verifyAkCollateral(input);
    }

    function test_rejectsRootAsAttestationKey() public {
        bytes[] memory certs = new bytes[](1);
        certs[0] = fixtures.readBytes(".root");
        AkPubCollateral memory input =
            AkPubCollateral(AkPubCollateralType.GcpCertChain, VerificationBackendType.Solidity, abi.encode(certs));
        vm.expectRevert(LeafCertIsCa.selector);
        verifier.verifyAkCollateral(input);
    }

    function test_rejectsRevokedAttestationCertificate() public {
        bytes[] memory roots = new bytes[](1);
        roots[0] = fixtures.readBytes(".root");
        tpm.updateCRL(fixtures.readBytes(".root_revoked"), roots);
        AkPubCollateral memory input = collateral("leaf");
        vm.expectRevert(CertificateAlreadyRevoked.selector);
        verifier.verifyAkCollateral(input);
    }
}
