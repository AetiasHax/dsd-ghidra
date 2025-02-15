package dsdghidra.loader;

import java.util.List;

import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;

public class DsRomLoaderData extends Structure {
    public DsLoaderModule arm9;
    public UnsafeList<DsLoaderModule> autoloads;
    public UnsafeList<DsLoaderModule> arm9_overlays;

    public DsLoaderModule arm7;
    public UnsafeList<DsLoaderModule> arm7_overlays;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("arm9", "autoloads", "arm9_overlays", "arm7", "arm7_overlays");
    }

    public DsLoaderModule[] getAutoloads() {
        return this.autoloads.getArray(new DsLoaderModule[0], DsLoaderModule::new);
    }

    public DsLoaderModule[] getArm9Overlays() {
        return this.arm9_overlays.getArray(new DsLoaderModule[0], DsLoaderModule::new);
    }

    public DsLoaderModule[] getArm7Overlays() {
        return this.arm7_overlays.getArray(new DsLoaderModule[0], DsLoaderModule::new);
    }
}
