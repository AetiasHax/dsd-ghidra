#!/bin/bash

if [ "$1" == "--debug" ]; then
    cargo build --target x86_64-unknown-linux-gnu
else
    cargo build --release --target x86_64-unknown-linux-gnu
fi

if [ "$1" == "--debug" ]; then
    cp target/x86_64-unknown-linux-gnu/debug/libdsd_ghidra.so dsd-ghidra/src/main/resources/linux-x86-64/
else
    cp target/x86_64-unknown-linux-gnu/release/libdsd_ghidra.so dsd-ghidra/src/main/resources/linux-x86-64/
fi