#!/bin/bash

if [ ! -f "Cross.toml"]; then
    echo "Cross.toml not found, aborting"
    exit 1
fi

if command -v cross &> /dev/null; then
    echo "Starting cross build"
else
    echo "'cross' executable not found, exiting"
    exit 1
fi

export RUSTFLAGS="-Z remap-cwd-prefix=."
if [ "$1" == "--debug" ]; then
    cross +nightly build --target x86_64-unknown-linux-gnu
    cross +nightly build --target x86_64-pc-windows-msvc
else
    cross +nightly build --release --target x86_64-unknown-linux-gnu
    cross +nightly build --release --target x86_64-pc-windows-msvc
fi
export RUSTFLAGS=""

if [ "$1" == "--debug" ]; then
    cp target/x86_64-unknown-linux-gnu/debug/libdsd_ghidra.so dsd-ghidra/src/main/resources/linux-x86-64/
    cp target/x86_64-pc-windows-msvc/debug/dsd_ghidra.dll dsd-ghidra/src/main/resources/win32-x86-64/
else
    cp target/x86_64-unknown-linux-gnu/release/libdsd_ghidra.so dsd-ghidra/src/main/resources/linux-x86-64/
    cp target/x86_64-pc-windows-msvc/release/dsd_ghidra.dll  dsd-ghidra/src/main/resources/win32-x86-64/
fi