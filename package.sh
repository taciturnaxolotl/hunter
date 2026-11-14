#!/usr/bin/env bash
# Builds release archives into dist/release: one per laptop platform, each
# holding that platform's hunter plus every hunter-linux-<arch> it pushes to
# boxes, so unpacking one archive is all a laptop needs. The bare target
# binaries and a SHA256SUMS file go alongside.
#
#   VERSION=v1.2.3 ./package.sh
set -euo pipefail
cd "$(dirname "$0")"
: "${VERSION:=dev}"
ver=${VERSION#v}

rm -rf dist
LAPTOP=0 VERSION="$VERSION" ./build.sh >/dev/null
out=dist/release
mkdir -p "$out"

LAPTOPS=(darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64)
for plat in "${LAPTOPS[@]}"; do
    os=${plat%/*} arch=${plat#*/}
    name="hunter_${ver}_${os}_${arch}"
    stage="dist/stage/$name"
    mkdir -p "$stage"
    exe=hunter
    [ "$os" = windows ] && exe=hunter.exe
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags="-s -w -X main.version=$ver" -o "$stage/$exe" .
    cp dist/hunter-linux-* README.md hosts.example "$stage/"
    [ -f LICENSE.md ] && cp LICENSE.md "$stage/"
    if [ "$os" = windows ]; then
        (cd dist/stage && zip -qr "../release/$name.zip" "$name")
    else
        tar -C dist/stage -czf "$out/$name.tar.gz" "$name"
    fi
done

for f in dist/hunter-linux-*; do
    cp "$f" "$out/$(basename "$f")"
done
(cd "$out" && { command -v sha256sum >/dev/null && sha256sum * || shasum -a 256 *; } > SHA256SUMS)
ls -lh "$out"
