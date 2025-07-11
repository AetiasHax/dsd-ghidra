param($arg0)

if ($arg0 -ne "debug") {
    cargo build --release --target x86_64-pc-windows-msvc
}
else {
    cargo build --target x86_64-pc-windows-msvc
}


if ($arg0 -ne "debug") {
    Copy-Item -Path target/x86_64-pc-windows-msvc/release/dsd_ghidra.dll -Destination dsd-ghidra/src/main/resources/win32-x86-64/
    Remove-Item -Path dsd-ghidra/src/main/resources/win32-x86-64/dsd_ghidra.pdb
}
else {
    Copy-Item -Path target/x86_64-pc-windows-msvc/debug/dsd_ghidra.dll -Destination dsd-ghidra/src/main/resources/win32-x86-64/
    Copy-Item -Path target/x86_64-pc-windows-msvc/debug/dsd_ghidra.pdb -Destination dsd-ghidra/src/main/resources/win32-x86-64/
}
