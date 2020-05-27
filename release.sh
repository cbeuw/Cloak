go get github.com/mitchellh/gox

mkdir -p release

read -rp "Cleaning $PWD/release directory. Proceed? [y/n]" res
if [ ! "$res" == "y" ]; then
	echo "Abort"
	exit 1
fi

rm -rf ./release/*


if [ -z "$v" ]; then
	echo "Version number cannot be null. Run with v=[version] release.sh"
	exit 1
fi

output="{{.Dir}}-{{.OS}}-{{.Arch}}-$v"
osarch="!darwin/arm !darwin/arm64 !darwin/386"

echo "Compiling:"

os="windows linux darwin"
arch="amd64 386 arm arm64 mips mips64 mipsle mips64le"
pushd cmd/ck-client || exit 1
gox -ldflags "-X main.version=${v}" -os="$os" -arch="$arch" -osarch="$osarch" -output="$output"
GOOS="linux" GOARCH="mips" GOMIPS="softfloat" go build -ldflags "-X main.version=${v}" -o ck-client-linux-mips_softfloat-"${v}"
GOOS="linux" GOARCH="mipsle" GOMIPS="softfloat" go build -ldflags "-X main.version=${v}" -o ck-client-linux-mipsle_softfloat-"${v}"
mv ck-client-* ../../release

os="linux"
arch="amd64 386 arm arm64"
pushd ../ck-server || exit 1
gox -ldflags "-X main.version=${v}" -os="$os" -arch="$arch" -osarch="$osarch" -output="$output"
mv ck-server-* ../../release
