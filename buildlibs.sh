#!/usr/bin/sh

if [ -z "$v" ]; then
	echo "Version number cannot be null. Run with v=[version] $0"
	exit 1
fi

mkdir -p build-lib

CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS="linux" GOARCH="arm64" go build -ldflags "-X main.version=${v}" -buildmode=c-shared -tags=external_main -o libck-client-arm64-linux.so ./cmd/ck-client
CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS="linux" GOARCH="arm"   go build -ldflags "-X main.version=${v}" -buildmode=c-shared -tags=external_main -o libck-client-arm-linux.so   ./cmd/ck-client
CC=x86_64-linux-gnu-gcc  CGO_ENABLED=1 GOOS="linux" GOARCH="amd64" go build -ldflags "-X main.version=${v}" -buildmode=c-shared -tags=external_main -o libck-client-amd64-linux.so ./cmd/ck-client
CC=x86_64-linux-gnu-gcc  CGO_ENABLED=1 GOOS="linux" GOARCH="386"   go build -ldflags "-X main.version=${v}" -buildmode=c-shared -tags=external_main -o libck-client-386-linux.so   ./cmd/ck-client

mv libck* build-lib
