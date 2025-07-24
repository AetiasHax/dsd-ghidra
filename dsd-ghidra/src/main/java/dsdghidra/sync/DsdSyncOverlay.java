package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncOverlay extends Structure {
    public short id;
    public DsdSyncModule module;

    public DsdSyncOverlay() {
    }

    public DsdSyncOverlay(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("id", "module");
    }
}
