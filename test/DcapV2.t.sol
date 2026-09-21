// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {TeeVerifierSnpTest} from "./TeeVerifier.t.sol";
import {TeeVerifier} from "../src/TeeVerifier.sol";
import {IDcapAttestationV2} from "../src/interfaces/external/IDcapAttestationV2.sol";
import {IntelTdxDcapV2ZkVerifierAdapter} from "../src/zk/ZkVerifierAdapters.sol";
import {IntelTdxDcapV2} from "../src/lib/IntelTdxDcapV2.sol";
import {OutputV2} from "../src/lib/dcap-v2/OutputV2.sol";
import {OutputV2Codec} from "../src/lib/dcap-v2/OutputV2Codec.sol";
import {TeeReport, TEEType, VerificationBackendType, TeeVerificationResult} from "../src/types/Evidence.sol";
import {
    IntelTdxDcapZkEvidence,
    IntelTdxDcapCompactOutputV1,
    ProgramBoundZkProof,
    ZkProofType
} from "../src/types/Zk.sol";

/// @dev Tests ABI forwarding and failure handling only, not cryptographic verification.
contract MockDcapV2Proof is IDcapAttestationV2 {
    bytes32 public expectedId;
    bool public fail;
    bool public substituteOutput;
    bool public zkV2Paused;

    function configure(bytes32 id, bool fail_, bool substitute_) external {
        expectedId = id;
        fail = fail_;
        substituteOutput = substitute_;
    }

    function verifyAndAttestOnChainV2(bytes calldata, uint32, bool)
        external
        payable
        returns (bool, bytes memory, bytes memory)
    {
        revert("unused");
    }

    function verifyAndAttestWithZKProofV2(
        bytes calldata journal,
        ZkCoProcessorType backend,
        bytes calldata proof,
        bytes32 id,
        uint32 tcbEval,
        bool minCheck
    ) external payable returns (bool, bytes memory) {
        require(backend == ZkCoProcessorType.Succinct && tcbEval == 0 && minCheck, "incorrect V2 arguments");
        require(keccak256(proof) == keccak256(hex"01020304"), "proof bytes changed");
        if (fail || id != expectedId) return (false, bytes("rejected"));
        if (substituteOutput) return (true, bytes.concat(journal, hex"00"));
        return (true, journal);
    }

    function programModeV2(ZkCoProcessorType, bytes32 id) external view returns (bool, bool) {
        return (id == expectedId, true);
    }

    function zkVerifierV2(ZkCoProcessorType, bytes4) external view returns (address) {
        return address(this);
    }
}

contract DcapV2CodecTest is Test {
    function decode(bytes memory data) external pure returns (OutputV2 memory) {
        return OutputV2Codec.decode(data);
    }

    function compact(bytes memory data) external pure returns (IntelTdxDcapCompactOutputV1 memory) {
        return IntelTdxDcapV2.decode(data);
    }

    function _fixture(string memory name) internal view returns (bytes memory) {
        bytes memory text = bytes(vm.readFile(string.concat("test/fixtures/dcap-v2/", name, ".hex")));
        // Preserve the upstream fixture file, including its final newline.
        if (text.length != 0 && text[text.length - 1] == 0x0a) {
            assembly ("memory-safe") { mstore(text, sub(mload(text), 1)) }
        }
        return vm.parseBytes(string(text));
    }

    function testFrozenUpstreamVectors() public view {
        string[3] memory names = ["sgx-empty", "tdx10-advisories", "tdx15-relaunch"];
        for (uint256 i; i < names.length; ++i) {
            bytes memory data = _fixture(names[i]);
            OutputV2 memory out = OutputV2Codec.decode(data);
            assertEq(OutputV2Codec.encode(out), data);
            assertEq(out.quoteVersion, i + 3);
            assertEq(out.quoteBodyType, i + 1);
        }
    }

    function testRejectsAllTruncationsAndTrailingBytes() public {
        bytes memory data = _fixture("sgx-empty");
        for (uint256 i; i < data.length; ++i) {
            bytes memory bad = new bytes(i);
            for (uint256 j; j < i; ++j) {
                bad[j] = data[j];
            }
            vm.expectRevert();
            this.decode(bad);
        }
        vm.expectRevert();
        this.decode(bytes.concat(data, hex"00"));
    }

    function testRejectsMutatedHeaders() public {
        bytes memory good = _fixture("sgx-empty");
        uint256[10] memory offsets = [uint256(0), 3, 4, 6, 8, 9, 32, 48, 49, 51];
        for (uint256 i; i < offsets.length; ++i) {
            bytes memory bad = bytes.concat(good);
            bad[offsets[i]] = 0xff;
            vm.expectRevert();
            this.decode(bad);
        }
        vm.expectRevert(); // SGX must not enter a TDX adapter.
        this.compact(good);
    }

    function testRejectsLegacyFormatsAndInvalidUtf8() public {
        bytes memory oldJournal = new bytes(333);
        oldJournal[1] = 0x83;
        vm.expectRevert();
        this.decode(oldJournal);
        bytes memory oldHeader = new bytes(289);
        vm.expectRevert();
        this.decode(oldHeader);
        OutputV2 memory out = OutputV2Codec.decode(_fixture("sgx-empty"));
        out.advisoryIDs = new string[](1);
        out.advisoryIDs[0] = "a";
        bytes memory data = OutputV2Codec.encode(out);
        data[317 + 128] = 0xff;
        vm.expectRevert();
        this.decode(data);
        data = OutputV2Codec.encode(out);
        data[data.length - 1] = 0x01; // Nonzero ABI padding.
        vm.expectRevert();
        this.decode(data);
    }

    function testAdvisoryHashSortsAndDeduplicatesLikeRust() public pure {
        string[] memory ids = new string[](3);
        ids[0] = "INTEL-SA-00002";
        ids[1] = "INTEL-SA-00001";
        ids[2] = ids[0];
        assertEq(
            IntelTdxDcapV2.advisoryIdsHash(ids), 0x74e331084383d7664e2286bc530b1be303d794a53fa76fe96418d6f00f6c6164
        );
    }
}

/// @dev Inherit the existing report/security tests, but run their ZK cases through V2.
/// The original TeeVerifierSnpTest continues running those cases through V1.
contract TeeVerifierDcapV2Test is TeeVerifierSnpTest {
    bytes32 internal constant V2_ID = keccak256("intel_tdx_dcap.v2.test");
    MockDcapV2Proof internal v2;
    IntelTdxDcapV2ZkVerifierAdapter internal v2Adapter;

    function setUp() public override {
        super.setUp();
        v2 = new MockDcapV2Proof();
        v2.configure(V2_ID, false, false);
        v2Adapter = new IntelTdxDcapV2ZkVerifierAdapter(v2);
        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap, VerificationBackendType.ZkSuccinct, V2_ID, address(v2Adapter), true
        );
    }

    function _tdxZkReport(bytes memory fullQuote, bytes memory body, uint16 bodyType)
        internal
        pure
        override
        returns (TeeReport memory)
    {
        OutputV2 memory out;
        out.formatMajorVersion = 2;
        out.formatMinorVersion = 1;
        out.quoteVersion = uint16(uint8(fullQuote[0]));
        out.quoteBodyType = bodyType;
        out.fullQuoteHash = keccak256(fullQuote);
        out.quoteBodyHash = keccak256(body);
        out.advisoryIDs = new string[](0);
        return TeeReport({
            verificationBackendType: VerificationBackendType.ZkSuccinct,
            teeType: TEEType.IntelTDX,
            data: abi.encode(
                IntelTdxDcapZkEvidence({
                    proof: ProgramBoundZkProof({
                        programIdentifier: V2_ID, output: OutputV2Codec.encode(out), proofBytes: hex"01020304"
                    }),
                    quoteBody: body
                })
            )
        });
    }

    function testV1AndV2RoutesCoexist() public {
        bytes memory quote = _td10Quote();
        bytes memory body = _tdxQuoteBody(quote, 48, 584);
        TeeVerificationResult memory oldResult = teeVerifier.verifyTeeReport(super._tdxZkReport(quote, body, 2));
        TeeVerificationResult memory newResult = teeVerifier.verifyTeeReport(_tdxZkReport(quote, body, 2));
        assertEq(oldResult.teeReportBytesHash, newResult.teeReportBytesHash);
        assertEq(oldResult.reportData, newResult.reportData);
        assertEq(dcap.lastProgramIdentifier(), TDX_PROGRAM_IDENTIFIER);
    }

    function testWrongProgramAndFormatAreRejected() public {
        bytes memory quote = _td10Quote();
        bytes memory body = _tdxQuoteBody(quote, 48, 584);
        TeeReport memory report = _tdxZkReport(quote, body, 2);
        IntelTdxDcapZkEvidence memory evidence = abi.decode(report.data, (IntelTdxDcapZkEvidence));
        evidence.proof.programIdentifier = TDX_PROGRAM_IDENTIFIER;
        report.data = abi.encode(evidence);
        vm.expectRevert();
        teeVerifier.verifyTeeReport(report);
        report = super._tdxZkReport(quote, body, 2);
        evidence = abi.decode(report.data, (IntelTdxDcapZkEvidence));
        evidence.proof.programIdentifier = V2_ID;
        evidence.proof.proofBytes = hex"01020304";
        report.data = abi.encode(evidence);
        vm.expectRevert();
        teeVerifier.verifyTeeReport(report);
        evidence.proof.programIdentifier = keccak256("unknown");
        report.data = abi.encode(evidence);
        vm.expectRevert();
        teeVerifier.verifyTeeReport(report);
    }

    function testV2ForwardsExactProgramAndRejectsFailedOrChangedOutput() public {
        bytes memory quote = _td10Quote();
        TeeReport memory report = _tdxZkReport(quote, _tdxQuoteBody(quote, 48, 584), 2);
        v2.configure(TDX_PROGRAM_IDENTIFIER, false, false);
        vm.expectRevert();
        teeVerifier.verifyTeeReport(report);
        v2.configure(V2_ID, true, false);
        vm.expectRevert();
        teeVerifier.verifyTeeReport(report);
        v2.configure(V2_ID, false, true);
        vm.expectRevert(IntelTdxDcapV2ZkVerifierAdapter.DcapVerifiedOutputMismatch.selector);
        teeVerifier.verifyTeeReport(report);
    }

    function testV2ZkKeepsAttributeAndTcbChecks() public {
        bytes memory quote = _td10Quote();
        bytes memory body = _tdxQuoteBody(quote, 48, 584);
        body[121] = 0x01;
        vm.expectRevert();
        teeVerifier.verifyTeeReport(_tdxZkReport(quote, body, 2));
        body[121] = 0;
        body[123] = 0;
        vm.expectRevert(TeeVerifier.TdxSeptVeDisableRequired.selector);
        teeVerifier.verifyTeeReport(_tdxZkReport(quote, body, 2));
        quote = _td15Quote();
        body = _tdxQuoteBody(quote, 54, 648);
        body[600] = 0x01;
        vm.expectRevert(TeeVerifier.TdxMigrationServiceTdNotSupported.selector);
        teeVerifier.verifyTeeReport(_tdxZkReport(quote, body, 3));
        body[600] = 0;
        TeeReport memory report = _tdxZkReport(quote, body, 3);
        IntelTdxDcapZkEvidence memory evidence = abi.decode(report.data, (IntelTdxDcapZkEvidence));
        evidence.proof.output[9] = 0x06;
        report.data = abi.encode(evidence);
        vm.expectRevert(abi.encodeWithSelector(TeeVerifier.DcapTcbStatusNotAccepted.selector, uint8(6)));
        teeVerifier.verifyTeeReport(report);
    }

    function testRawV2RejectsBodyOrFullQuoteSubstitution() public {
        bytes memory quote = _td10Quote();
        (, bytes memory output, bytes memory body) = dcap.verifyAndAttestOnChainV2(quote, 0, true);
        body[0] = 0x01;
        vm.mockCall(
            address(dcap),
            abi.encodeCall(IDcapAttestationV2.verifyAndAttestOnChainV2, (quote, 0, true)),
            abi.encode(true, output, body)
        );
        vm.expectRevert();
        teeVerifier.verifyTeeReport(_tdxReport(quote));
        body[0] = 0;
        output[253] = bytes1(uint8(output[253]) ^ 1);
        vm.mockCall(
            address(dcap),
            abi.encodeCall(IDcapAttestationV2.verifyAndAttestOnChainV2, (quote, 0, true)),
            abi.encode(true, output, body)
        );
        vm.expectRevert();
        teeVerifier.verifyTeeReport(_tdxReport(quote));
    }
}
