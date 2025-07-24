package dsdghidra.sync;

import org.jetbrains.annotations.NotNull;

public enum DsdSyncAutoloadKind {
    Itcm,
    Dtcm,
    Unknown;

    public static final @NotNull DsdSyncAutoloadKind[] VALUES = DsdSyncAutoloadKind.values();
}
