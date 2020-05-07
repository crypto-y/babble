#!/usr/bin/env bash
set -e
echo "" > coverage.txt
for d in $(go list ./... | grep -v vendor); do
    go test -coverprofile=profile.out -coverpkg=github.com/yyforyongyu/babble/dh,github.com/yyforyongyu/babble/cipher,github.com/yyforyongyu/babble/pattern,github.com/yyforyongyu/babble/hash,github.com/yyforyongyu/babble/rekey $d
    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done