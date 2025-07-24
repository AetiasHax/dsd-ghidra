package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncDataRange extends Structure {
    public int start;
    public int end;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("start", "end");
    }

    public DsdSyncDataRange() {
    }

    public DsdSyncDataRange(@NotNull Pointer p) {
        super(p);
        this.read();
    }
}
