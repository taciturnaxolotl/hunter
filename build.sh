#!/usr/bin/env bash
# Builds static hunter binaries for every target arch plus one for this
# machine. Run before competition day; dist/ is what gets pushed to boxes.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
export CGO_ENABLED=0
for arch in amd64 arm64 386; do
    GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w' -o "dist/hunter-linux-$arch" .
done
go build -trimpath -ldflags='-s -w' -o dist/hunter .
ls -lh dist/
