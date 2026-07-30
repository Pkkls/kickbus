#!/bin/sh
# Cross-compile for a RISC-V board. Static binary, no runtime dependency.
set -e
cd "$(dirname "$0")"
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -ldflags="-s -w" -o kickbus-riscv64 .
echo "OK -> $(pwd)/kickbus-riscv64  ($(du -h kickbus-riscv64 | cut -f1))"
