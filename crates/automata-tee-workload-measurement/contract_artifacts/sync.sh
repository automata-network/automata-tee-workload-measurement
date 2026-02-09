#!/bin/bash

function sync_file() {
    mkdir $1.sol
    cp ../../../out/$1.sol/$1.json ./$1.sol
}

sync_file WorkloadRegistry
sync_file SessionRegistry
sync_file BaseImageRegistry
sync_file TpmAttestation