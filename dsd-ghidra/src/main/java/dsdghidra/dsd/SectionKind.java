package dsdghidra.dsd;

import org.jetbrains.annotations.NotNull;

public enum SectionKind {
    Code,
    Data,
    Rodata,
    Bss;

    public static final @NotNull SectionKind[] VALUES = SectionKind.values();

    public boolean isBss() {
        return this == SectionKind.Bss;
    }

    public boolean isWriteable() {
        return this != SectionKind.Code && this != SectionKind.Rodata;
    }

    public boolean isExecutable() {
        return this == SectionKind.Code;
    }
}
