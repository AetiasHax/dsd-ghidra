package dsdghidra.sync;

import org.jetbrains.annotations.NotNull;

public enum DsdSyncRelocationModule {
    None,
    Overlays,
    Main,
    Itcm,
    Dtcm,
    Autoload;

    public static final @NotNull DsdSyncRelocationModule[] VALUES = DsdSyncRelocationModule.values();
}
