#!/bin/bash

dirList=(
    "./client/functions"
    "./crypto"
    "./server/auth"
    "./server/db"
    "./server/functions"
    "./shared"
    "./log"
    )

runTests() {
    pushd $1
    go test
    ret=$?
    popd
    return $ret
}

code=0

for d in "${dirList[@]}"; do
    if [[ -d $d ]]; then
        runTests "$d"
        code=$(($code + $?))
    fi
done

echo -ne "\n\n"

if [[ $code == 0 ]]; then
    echo -e "------- ALL TESTS PASSED -------\n"
    exit 0
else
    echo -e "--- ONE OR MORE TESTS FAILED ---\n"
    exit 2
fi

