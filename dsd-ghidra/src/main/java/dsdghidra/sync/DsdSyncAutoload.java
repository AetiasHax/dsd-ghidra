package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncAutoload extends Structure {
    public int kind;
    public int index;
    public DsdSyncModule module;

    public DsdSyncAutoload() {
    }

    public DsdSyncAutoload(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("kind", "index", "module");
    }

    public @NotNull DsdSyncAutoloadKind getKind() {
        return DsdSyncAutoloadKind.VALUES[kind];
    }
}
