#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
rm -rf dist
mkdir -p dist

build() { # $1=GOOS $2=GOARCH $3=ext
  local out="dist/cork_${1}_${2}${3}"
  echo "building $out (cork $VERSION)"
  GOOS="$1" GOARCH="$2" CGO_ENABLED=0 \
    go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$out" ./cmd/cork
}

build linux   amd64 ""
build windows amd64 ".exe"

(cd dist && sha256sum cork_* > SHA256SUMS)
echo "done: dist/"
