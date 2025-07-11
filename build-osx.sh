#!/bin/bash

ARG0=$1
ARCH=$(uname -m)

if [ "$ARCH" = "arm64" ]; then
    cargo build --target aarch64-apple-darwin

    cp target/aarch64-apple-darwin/debug/libdsd_ghidra.dylib dsd-ghidra/src/main/resources/darwin-aarch64/

elif [ "$ARCH" = "x86_64" ]; then
    cargo build --target x86_64-apple-darwin

    cp target/x86_64-apple-darwin/debug/libdsd_ghidra.dylib dsd-ghidra/src/main/resources/darwin-x86-64/
else
    echo "Unknown architecture: $ARCH"
    exit 1
fi