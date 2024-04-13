#!/usr/bin/env bash

set -eu

go install github.com/mitchellh/gox@latest

mkdir -p release

rm -f ./release/*

if [ -z "$v" ]; then
	echo "Version number cannot be null. Run with v=[version] release.sh"
	exit 1
fi

output="{{.Dir}}-{{.OS}}-{{.Arch}}-$v"
osarch="!darwin/arm !darwin/386"

echo "Compiling:"

os="windows linux darwin"
arch="amd64 386 arm arm64 mips mips64 mipsle mips64le"
pushd cmd/ck-client
CGO_ENABLED=0 gox -ldflags "-X main.version=${v}" -os="$os" -arch="$arch" -osarch="$osarch" -output="$output"
CGO_ENABLED=0 GOOS="linux" GOARCH="mips" GOMIPS="softfloat" go build -ldflags "-X main.version=${v}" -o ck-client-linux-mips_softfloat-"${v}"
CGO_ENABLED=0 GOOS="linux" GOARCH="mipsle" GOMIPS="softfloat" go build -ldflags "-X main.version=${v}" -o ck-client-linux-mipsle_softfloat-"${v}"
mv ck-client-* ../../release
popd

os="linux"
arch="amd64 386 arm arm64"
pushd cmd/ck-server
CGO_ENABLED=0 gox -ldflags "-X main.version=${v}" -os="$os" -arch="$arch" -osarch="$osarch" -output="$output"
mv ck-server-* ../../release
popd

sha256sum release/*