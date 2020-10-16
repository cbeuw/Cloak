#!/bin/bash
set -xe

## Build fuzzing targets
## go-fuzz doesn't support modules for now, so ensure we do everything
## in the old style GOPATH way
export GO111MODULE="off"

## Install go-fuzz
go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build

# download dependencies into ${GOPATH}
# -d : only download (don't install)f
# -v : verbose
# -u : use the latest version
# will be different if you use vendoring or a dependency manager
# like godep
go get -d -v -u ./...

cd internal/multiplex
go-fuzz-build -libfuzzer -o multiplex.a .
clang -fsanitize=fuzzer multiplex.a -o cloak-multiplex

## Install fuzzit latest version:
wget -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/latest/download/fuzzit_Linux_x86_64
chmod a+x fuzzit

## upload fuzz target for long fuzz testing on fuzzit.dev server or run locally for regression
./fuzzit create job --type ${1} cbeuw/cloak-multiplex cloak-multiplex