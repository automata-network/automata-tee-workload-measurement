# DCAP compact OutputV2 codec

Source: https://github.com/automata-network/automata-dcap-attestation
Commit: `8be7030f092ea5d0429e1baa487ac9ff1c6a55a9`
Files: `evm/contracts/types/OutputV2.sol`, `evm/contracts/utils/OutputV2Codec.sol`.
License: MIT, retained in source headers.

The struct is unchanged. The codec accepts memory instead of calldata because
external verifier return values reside in memory. Fixed-width reads use the
project's checked LibBytes functions, and the advisory slice uses LibBytes.slice.
Encoding, field validation and UTF-8 checks retain upstream behavior.
Format 2.1 here means the compact 317-byte header, not the prior inline-body draft.

The encoder concatenates two packed segments to avoid a Solidity via-IR stack
limit when inlined in tests. Frozen vectors check byte-for-byte parity.
