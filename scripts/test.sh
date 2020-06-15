#!/usr/bin/env bash
set -e
echo "" > coverage.txt
for d in $(go list ./... | grep -v vendor); do
    go test -coverprofile=profile.out -coverpkg=github.com/crypto-y/babble,github.com/crypto-y/babble/dh,github.com/crypto-y/babble/cipher,github.com/crypto-y/babble/pattern,github.com/crypto-y/babble/hash,github.com/crypto-y/babble/rekey $d
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done