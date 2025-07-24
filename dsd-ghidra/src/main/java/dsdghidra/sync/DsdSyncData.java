package dsdghidra.sync;

import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncData extends Structure {
    public DsdSyncModule arm9;
    public UnsafeList<DsdSyncAutoload> autoloads;
    public UnsafeList<DsdSyncOverlay> arm9_overlays;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("arm9", "autoloads", "arm9_overlays");
    }

    public @NotNull DsdSyncAutoload[] getAutoloads() {
        return autoloads.getArray(new DsdSyncAutoload[0], DsdSyncAutoload::new);
    }

    public @NotNull DsdSyncOverlay[] getArm9Overlays() {
        return arm9_overlays.getArray(new DsdSyncOverlay[0], DsdSyncOverlay::new);
    }
}
