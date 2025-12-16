#!/bin/bash

set -e

usage() {
    echo "Usage: $0 <owner_address> <p256_verifier_address>"
    echo ""
    echo "Generates initialize() calldata for CVMRegistry contract"
    echo ""
    echo "Arguments:"
    echo "  owner_address         The address of the contract owner"
    echo "  p256_verifier_address The address of the P256 verifier contract"
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

OWNER_ADDRESS=$1
P256_VERIFIER_ADDRESS=$2

# Validate addresses (basic check for 0x prefix and length)
if [[ ! "$OWNER_ADDRESS" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
    echo "Error: Invalid owner address format"
    exit 1
fi

if [[ ! "$P256_VERIFIER_ADDRESS" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
    echo "Error: Invalid p256 verifier address format"
    exit 1
fi

# Generate calldata using cast
# initialize(address,address)
CALLDATA=$(cast calldata "initialize(address,address)" "$OWNER_ADDRESS" "$P256_VERIFIER_ADDRESS")

echo "$CALLDATA"
