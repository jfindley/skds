#!/bin/bash

dirList=(
    "./crypto"
    "./server/auth"
    "./server/db"
    "./server/functions"
    "./shared"
    )

runTests() {
    pushd $1
    go test
    popd
}

for d in "${dirList[@]}"; do
    if [[ -d $d ]]; then
        runTests "$d"
    fi
done