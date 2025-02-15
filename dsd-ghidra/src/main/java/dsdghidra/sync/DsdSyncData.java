package dsdghidra.sync;

import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;

import java.util.List;

public class DsdSyncData extends Structure {
    public DsdSyncModule arm9;
    public UnsafeList<DsdSyncAutoload> autoloads;
    public UnsafeList<DsdSyncOverlay> arm9_overlays;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("arm9", "autoloads", "arm9_overlays");
    }

    public DsdSyncAutoload[] getAutoloads() {
        return autoloads.getArray(new DsdSyncAutoload[0], DsdSyncAutoload::new);
    }

    public DsdSyncOverlay[] getArm9Overlays() {
        return arm9_overlays.getArray(new DsdSyncOverlay[0], DsdSyncOverlay::new);
    }
}
