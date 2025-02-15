package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.dsd.DsdRelocationKind;
import dsdghidra.types.UnsafeU16List;

import java.util.Arrays;
import java.util.List;

public class DsdSyncRelocation extends Structure {
    public int from;
    public int to;
    public byte kind;
    public int module;
    public UnsafeU16List overlays;
    public boolean conditional;

    public DsdSyncRelocation() {
    }

    public DsdSyncRelocation(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("from", "to", "kind", "module", "overlays", "conditional");
    }

    public DsdRelocationKind getKind() {
        return DsdRelocationKind.VALUES[kind];
    }

    public DsdSyncRelocationModule getModule() {
        return DsdSyncRelocationModule.VALUES[this.module];
    }

    @Override
    public String toString() {
        return "DsdSyncRelocation{" +
            "from=" + Integer.toHexString(from) +
            ", to=" + Integer.toHexString(to) +
            ", kind=" + getKind() +
            ", module=" + getModule() +
            ", overlays=" + Arrays.toString(overlays.getArray()) +
            ", conditional=" + conditional +
            '}';
    }
}
