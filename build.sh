#!/usr/bin/env bash
# Builds static hunter binaries for every target arch plus one for this
# machine. Run before competition day; dist/ is what gets pushed to boxes.
#
# VERSION=v1.2.3 stamps the version. LAPTOP=0 skips the build for this
# machine (the release workflow builds laptop binaries per platform).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
export CGO_ENABLED=0
ldflags="-s -w"
if [ -n "${VERSION:-}" ]; then
    ldflags+=" -X main.version=${VERSION#v}"
fi

# keep in sync with unameArch in internal/remote/remote.go
for arch in amd64 arm64 386 arm riscv64 ppc64le s390x; do
    # GOARM=6 runs on both armv6l and armv7l boxes
    GOOS=linux GOARCH=$arch GOARM=6 go build -trimpath -ldflags="$ldflags" -o "dist/hunter-linux-$arch" .
done
if [ "${LAPTOP:-1}" = 1 ]; then
    go build -trimpath -ldflags="$ldflags" -o dist/hunter .
fi
ls -lh dist/
