package dsdghidra;

import com.sun.jna.Native;
import com.sun.jna.Library;
import com.sun.jna.Pointer;
import dsdghidra.loader.DsRomLoaderData;
import dsdghidra.sync.DsdSyncData;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public interface DsdGhidra extends Library {
    @SuppressWarnings("deprecation")
    DsdGhidra INSTANCE = Native.loadLibrary("dsd_ghidra", DsdGhidra.class);

    boolean is_valid_ds_rom(byte[] bytes, int length);

    boolean get_loader_data(byte[] bytes, int length, @NotNull DsRomLoaderData data, @Nullable Pointer error);

    boolean free_loader_data(@NotNull DsRomLoaderData data, @Nullable Pointer error);

    boolean get_dsd_sync_data(String config_path, @NotNull DsdSyncData data, @Nullable Pointer error);

    boolean free_dsd_sync_data(@NotNull DsdSyncData data, @Nullable Pointer error);

    void free_error(@Nullable Pointer error);
}
