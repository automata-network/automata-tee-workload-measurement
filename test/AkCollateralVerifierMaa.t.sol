// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AkCollateralVerifier} from "../src/bases/AkCollateralVerifier.sol";
import {AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
import {MaaKeyRegistry} from "../src/MaaKeyRegistry.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {AkPubCollateral, AkPubCollateralType} from "../src/types/Evidence.sol";
import {PublicIdentity} from "../src/types/Common.sol";
import {ALGO_ID_ES256K, ALGO_ID_RS256} from "../src/types/Constants.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {Base64} from "@solady/utils/Base64.sol";

/// @title AkCollateralVerifierMaaTest
/// @notice Exercises the AzureMaaJwt verification path end-to-end. The RSA
///         signature verification step is mocked through vm.mockCall on the SignatureVerifier
///         — the surrounding plumbing (JWT split, base64url decode, JSON field extraction,
///         hex decoding, binding check, HCLAkPub parse from hclVarData) is exercised against
///         actual encoded inputs.
contract AkCollateralVerifierMaaTest is Test {
    SignatureVerifier internal signatureVerifier;
    MaaKeyRegistry internal registry;
    AkCollateralVerifier internal verifier;

    address internal constant owner = address(0xABCD);
    PublicIdentity internal ownerIdentity;

    string internal constant TEST_KID = "test-kid";
    bytes32 internal constant TEST_KID_HASH = keccak256(bytes("test-kid"));
    bytes internal constant TEST_PKCS1_PUBKEY = hex"30820122300d06092a864886f70d01010105000382010f00";
    bytes32 internal constant TEST_ISSUER_HASH = keccak256(bytes("https://test-issuer.attest.azure.net"));
    string internal constant TEST_ISSUER_URL = "https://test-issuer.attest.azure.net";

    function setUp() public {
        ownerIdentity = PublicIdentity({typeId: ALGO_ID_ES256K, key: hex"04aabbccdd"});

        vm.startPrank(owner);
        signatureVerifier = new SignatureVerifier(address(0xdead));
        MaaKeyRegistry impl = new MaaKeyRegistry();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(MaaKeyRegistry.initialize, (owner)));
        registry = MaaKeyRegistry(address(proxy));
        vm.stopPrank();

        // sentinel for ITpmAttestation; Azure path does not touch it
        verifier = new AkCollateralVerifier(registry, signatureVerifier, ITpmAttestation(address(0xdead)));

        // Default: signatureVerifier.verify always returns true. Individual tests override.
        // (This signatureVerifier is the AkCollateralVerifier's JWT-verification dependency;
        // MaaKeyRegistry no longer consults it now that admin auth is onlyOwner.)
        vm.mockCall(
            address(signatureVerifier), abi.encodeWithSelector(signatureVerifier.verify.selector), abi.encode(true)
        );

        // Pre-register the MAA signing key shared by all happy-path tests.
        vm.prank(owner);
        registry.upsertMaaSigningKey(
            TEST_KID_HASH, TEST_PKCS1_PUBKEY, TEST_ISSUER_HASH, uint64(block.timestamp + 365 days)
        );
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Happy path
    // ───────────────────────────────────────────────────────────────────────────

    function test_happyPath_tdx() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportDataHex = _bytes32ToHex64Lower(bindingHash);
        // append 64 zero hex chars for the zero padding required by §8.3.1
        string memory reportData =
            string.concat(reportDataHex, "0000000000000000000000000000000000000000000000000000000000000000");

        bytes memory jwt = _buildJwt(_tdxClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        AkPubCollateral memory c = AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data});

        AkCollateralVerificationResult memory r = verifier.verifyAkCollateral(c);

        assertTrue(r.valid, "valid");
        assertEq(r.bindingHash, bindingHash, "bindingHash equals sha256(hclVarData)");
        assertEq(r.akPub.typeId, ALGO_ID_RS256, "akPub typeId is RS256");
        assertGt(r.akPub.key.length, 0, "akPub key non-empty");
    }

    function test_happyPath_snp() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        bytes memory jwt = _buildJwt(_snpClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        AkPubCollateral memory c = AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data});

        AkCollateralVerificationResult memory r = verifier.verifyAkCollateral(c);

        assertTrue(r.valid, "valid");
        assertEq(r.bindingHash, bindingHash, "bindingHash matches");
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Negative cases
    // ───────────────────────────────────────────────────────────────────────────

    function test_revert_when_alg_not_RS256() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // header with alg=HS256 instead of RS256
        string memory header = string.concat('{"alg":"HS256","kid":"', TEST_KID, '"}');
        string memory claims = _tdxClaims(reportData);
        bytes memory jwt = _composeJwt(header, claims, hex"deadbeef");
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtAlgUnsupported.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_kid_not_registered() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        string memory header = '{"alg":"RS256","kid":"unknown-kid"}';
        string memory claims = _tdxClaims(reportData);
        bytes memory jwt = _composeJwt(header, claims, hex"deadbeef");
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaKidNotRegistered.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_kid_revoked() public {
        vm.prank(owner);
        registry.revokeMaaSigningKey(TEST_KID_HASH);

        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        bytes memory jwt = _buildJwt(_tdxClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaKidNotRegistered.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_issuer_mismatch() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // claims with the wrong issuer
        string memory claims = string.concat(
            '{"iss":"https://wrong-issuer.attest.azure.net",',
            '"x-ms-attestation-type":"tdxvm",',
            '"x-ms-compliance-status":"azure-compliant-cvm",',
            '"tdx_report_data":"',
            reportData,
            '"}'
        );
        bytes memory jwt = _buildJwt(claims);
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtIssuerMismatch.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_compliance_status_wrong() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        string memory claims = string.concat(
            '{"iss":"',
            TEST_ISSUER_URL,
            '","x-ms-attestation-type":"tdxvm",',
            '"x-ms-compliance-status":"azure-noncompliant",',
            '"tdx_report_data":"',
            reportData,
            '"}'
        );
        bytes memory jwt = _buildJwt(claims);
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtComplianceFailed.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_signature_invalid() public {
        // override the global mock to return false
        vm.mockCall(
            address(signatureVerifier), abi.encodeWithSelector(signatureVerifier.verify.selector), abi.encode(false)
        );

        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        bytes memory jwt = _buildJwt(_tdxClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtSignatureInvalid.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_binding_hash_mismatch() public {
        bytes memory hclVarData = _buildHclVarData();
        // use a different binding hash than sha256(hclVarData)
        bytes32 wrongBindingHash = keccak256("wrong");
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(wrongBindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        bytes memory jwt = _buildJwt(_tdxClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtBindingMismatch.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_report_data_padding_nonzero() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        // non-zero second half
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );

        bytes memory jwt = _buildJwt(_tdxClaims(reportData));
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtReportDataMalformed.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_jwt_malformed_two_dots_missing() public {
        bytes memory hclVarData = _buildHclVarData();
        // missing one dot
        bytes memory jwt = bytes("aGVhZGVy.aGVsbG8");
        bytes memory data = abi.encode(jwt, hclVarData);

        // single-dot JWT triggers the "missing second dot" structural check
        vm.expectRevert(abi.encodeWithSelector(AkCollateralVerifier.MaaJwtStructureInvalid.selector, uint8(2)));
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    function test_revert_when_attestation_type_unsupported() public {
        bytes memory hclVarData = _buildHclVarData();
        bytes32 bindingHash = sha256(hclVarData);
        string memory reportData = string.concat(
            _bytes32ToHex64Lower(bindingHash), "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // attestation-type is neither tdxvm nor sevsnpvm
        string memory claims = string.concat(
            '{"iss":"',
            TEST_ISSUER_URL,
            '","x-ms-attestation-type":"unknownvm",',
            '"x-ms-compliance-status":"azure-compliant-cvm",',
            '"tdx_report_data":"',
            reportData,
            '"}'
        );
        bytes memory jwt = _buildJwt(claims);
        bytes memory data = abi.encode(jwt, hclVarData);

        vm.expectPartialRevert(AkCollateralVerifier.MaaJwtAttestationTypeUnsupported.selector);
        verifier.verifyAkCollateral(AkPubCollateral({akPubCollateralType: AkPubCollateralType.AzureMaaJwt, data: data}));
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Helpers
    // ───────────────────────────────────────────────────────────────────────────

    /// @dev Builds a minimal hclVarData containing the HCLAkPub JWK that the §14.3-scoped
    ///      parser expects. The RSA modulus is 256 random-looking bytes with an odd LSB
    ///      (passes LibX509.validateRsa); exponent is 65537.
    function _buildHclVarData() internal pure returns (bytes memory) {
        bytes memory n = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            // mix of nonzero bytes; ensure first byte high-bit and last byte odd
            n[i] = bytes1(uint8(0x80 | (i & 0x7e) | (i == 255 ? 0x01 : 0x00)));
        }
        n[255] = 0x81;
        bytes memory e = hex"010001";

        string memory nB64 = Base64.encode(n, true, true);
        string memory eB64 = Base64.encode(e, true, true);

        return bytes(string.concat('{"keys":[{"kid":"HCLAkPub","kty":"RSA","e":"', eB64, '","n":"', nB64, '"}]}'));
    }

    function _tdxClaims(string memory reportDataHex) internal pure returns (string memory) {
        return string.concat(
            '{"iss":"',
            TEST_ISSUER_URL,
            '","x-ms-attestation-type":"tdxvm",',
            '"x-ms-compliance-status":"azure-compliant-cvm",',
            '"tdx_report_data":"',
            reportDataHex,
            '"}'
        );
    }

    function _snpClaims(string memory reportDataHex) internal pure returns (string memory) {
        return string.concat(
            '{"iss":"',
            TEST_ISSUER_URL,
            '","x-ms-attestation-type":"sevsnpvm",',
            '"x-ms-compliance-status":"azure-compliant-cvm",',
            '"x-ms-sevsnpvm-reportdata":"',
            reportDataHex,
            '"}'
        );
    }

    function _buildJwt(string memory claims) internal pure returns (bytes memory) {
        string memory header = string.concat('{"alg":"RS256","kid":"', TEST_KID, '"}');
        return _composeJwt(header, claims, hex"deadbeef");
    }

    function _composeJwt(string memory header, string memory claims, bytes memory sig)
        internal
        pure
        returns (bytes memory)
    {
        // base64url, no padding
        string memory hb = Base64.encode(bytes(header), true, true);
        string memory cb = Base64.encode(bytes(claims), true, true);
        string memory sb = Base64.encode(sig, true, true);
        return bytes(string.concat(hb, ".", cb, ".", sb));
    }

    /// @dev Encodes a bytes32 as a lowercase 64-character hex string with no `0x` prefix.
    function _bytes32ToHex64Lower(bytes32 v) internal pure returns (string memory) {
        return LibString.toHexStringNoPrefix(uint256(v), 32);
    }
}
