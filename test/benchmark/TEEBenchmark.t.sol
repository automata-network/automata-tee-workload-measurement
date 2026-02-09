// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {Test, console} from "forge-std/Test.sol";

contract TEEBenchmarkTest is Test {
    // DCAP quote signature offset and length
    uint256 constant DCAP_QE_SIG_OFFSET = 1154;
    uint256 constant DCAP_QE_SIG_LENGTH = 64;

    // SEV signature offset and length
    uint256 constant SEV_SIG_OFFSET = 0x02A0; // 672 in decimal
    uint256 constant SEV_SIG_LENGTH = 96;

    /// @notice Benchmark keccak256 hashing of DCAP quote
    function test_keccak256_dcap() public {
        // Load the quote file outside of gas metering
        vm.pauseGasMetering();
        bytes memory quote = vm.readFileBinary("test/benchmark/quotev4.bin");
        console.log("Report length:", quote.length);
        vm.resumeGasMetering();

        // Measure gas for keccak256 operation
        uint256 gasBefore = gasleft();
        bytes32 hash = keccak256(quote);
        uint256 gasAfter = gasleft();

        emit log_named_uint("keccak256_dcap_gas", gasBefore - gasAfter);
        emit log_named_bytes32("keccak256_dcap_hash", hash);
    }

    /// @notice Benchmark keccak256 hashing of SEV attestation
    function test_keccak256_sev() public {
        // Load the SEV file outside of gas metering
        vm.pauseGasMetering();
        bytes memory sevData = vm.readFileBinary("test/benchmark/sev.bin");
        console.log("Report length:", sevData.length);
        vm.resumeGasMetering();

        // Measure gas for keccak256 operation
        uint256 gasBefore = gasleft();
        bytes32 hash = keccak256(sevData);
        uint256 gasAfter = gasleft();

        emit log_named_uint("keccak256_sev_gas", gasBefore - gasAfter);
        emit log_named_bytes32("keccak256_sev_hash", hash);
    }

    /// @notice Benchmark extracting QE signature from DCAP quote and storing to memory
    function test_extract_dcap_qe_signature() public {
        // Load the quote file outside of gas metering
        vm.pauseGasMetering();
        bytes memory quote = vm.readFileBinary("test/benchmark/quotev4.bin");
        bytes memory signature = new bytes(DCAP_QE_SIG_LENGTH);
        vm.resumeGasMetering();

        // Measure gas for extraction and memory store
        uint256 gasBefore = gasleft();
        assembly {
            // Load 64 bytes from quote at offset DCAP_QE_SIG_OFFSET
            // quote pointer points to length, so add 32 for data start
            let srcPtr := add(add(quote, 32), DCAP_QE_SIG_OFFSET)
            let dstPtr := add(signature, 32)

            // Copy 64 bytes (2 words of 32 bytes each)
            mstore(dstPtr, mload(srcPtr))
            mstore(add(dstPtr, 32), mload(add(srcPtr, 32)))
        }
        uint256 gasAfter = gasleft();

        emit log_named_uint("extract_dcap_qe_signature_gas", gasBefore - gasAfter);
        emit log_named_bytes("dcap_qe_signature", signature);
    }

    /// @notice Benchmark extracting signature from SEV attestation and storing to memory
    function test_extract_sev_signature() public {
        // Load the SEV file outside of gas metering
        vm.pauseGasMetering();
        bytes memory sevData = vm.readFileBinary("test/benchmark/sev.bin");
        bytes memory signature = new bytes(SEV_SIG_LENGTH);
        vm.resumeGasMetering();

        // Measure gas for extraction and memory store
        uint256 gasBefore = gasleft();
        assembly {
            // Load 96 bytes from sevData at offset SEV_SIG_OFFSET
            // sevData pointer points to length, so add 32 for data start
            let srcPtr := add(add(sevData, 32), SEV_SIG_OFFSET)
            let dstPtr := add(signature, 32)

            // Copy 96 bytes (3 words of 32 bytes each)
            mstore(dstPtr, mload(srcPtr))
            mstore(add(dstPtr, 32), mload(add(srcPtr, 32)))
            mstore(add(dstPtr, 64), mload(add(srcPtr, 64)))
        }
        uint256 gasAfter = gasleft();

        emit log_named_uint("extract_sev_signature_gas", gasBefore - gasAfter);
        emit log_named_bytes("sev_signature", signature);
    }
}
