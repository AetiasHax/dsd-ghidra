package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.List;

public class DsdSyncAutoload extends Structure {
    public int kind;
    public int index;
    public DsdSyncModule module;

    public DsdSyncAutoload() {
    }

    public DsdSyncAutoload(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("kind", "index", "module");
    }

    public DsdSyncAutoloadKind getKind() {
        return DsdSyncAutoloadKind.VALUES[kind];
    }
}
