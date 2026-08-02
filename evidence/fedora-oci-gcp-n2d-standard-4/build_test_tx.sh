#!/bin/bash
# SEV-SNP test transaction for the anvil-fork (chain 31337).
#
# Validates the new SNP path on the deployed TeeVerifier end-to-end with a REAL proof.
#
# Prereqs (you generate these with the SDK RiscZero prover, over THIS exact report):
#   - report.bin / report.hex : the 1184-byte SNP report from this CVM (already saved here).
#   - output.hex : the prover's packed zkVM journal (.raw_proof.journal), 0x-prefixed.
#   - proof.hex  : the on-chain proof blob (.onchain_proof), 0x-prefixed.
# The journal's trailing 32 bytes MUST equal keccak256(report) or the on-chain
# hash-binding check reverts SnpReportHashMismatch (0x9edc9724).
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
DIR="$(cd "$(dirname "$0")" && pwd)"
RPC=http://139.99.100.76:8545
TEE=0xa3A0044535140d07BfF6a80374930963e521a6b7   # new TeeVerifier (SNP journal-layout fix)

REPORT=$(cat "$DIR/report.hex")
[ -f "$DIR/output.hex" ] || { echo "ERROR: missing output.hex — prove over report.bin first."; exit 1; }
[ -f "$DIR/proof.hex"  ] || { echo "ERROR: missing proof.hex."; exit 1; }
OUTPUT=$(cat "$DIR/output.hex")
PROOF=$(cat "$DIR/proof.hex")

echo "expected reportHash = keccak256(report) = $(cast keccak "$REPORT")"
echo "journal trailing 32 bytes               = 0x${OUTPUT: -64}   (must match above)"
echo

# teeReport.data = abi.encode(AmdSevSnpZkEvidence{ proof, rawReport })
SNP=$(cast abi-encode "x((bytes,bytes,bytes))" "($OUTPUT,$PROOF,$REPORT)")

echo "=== isolated TeeVerifier.verifyTeeReport(ZkSuccinct=2, AmdSevSnp=1) on $TEE ==="
if cast call "$TEE" "verifyTeeReport((uint8,uint8,bytes))((bool,bytes,uint8))" "(2,1,$SNP)" --rpc-url "$RPC"; then
  echo "PASS — proof verified, SDK journal decoded, keccak256(rawReport)==reportHash, full report returned."
else
  echo "REVERTED — interpret the selector:"
  echo "  0x9edc9724 SnpReportHashMismatch(expected,actual)  -> report bytes != what the proof attests"
  echo "  0x7ba2fe16 SnpVerificationFailed(result)           -> 2=InvalidTimestamp (stale), 1=RootCertNotTrusted"
  echo "  0x194d137a UnsupportedBackendType                  -> backend/teeType wrong"
fi
