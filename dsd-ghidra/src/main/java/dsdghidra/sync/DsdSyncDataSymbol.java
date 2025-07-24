package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeString;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncDataSymbol extends Structure {
    public UnsafeString name;
    public int address;
    public int kind;
    public int count;

    public DsdSyncDataSymbol() {
    }

    public DsdSyncDataSymbol(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("name", "address", "kind", "count");
    }

    public @NotNull DsdSyncDataKind getKind() {
        return DsdSyncDataKind.VALUES[kind];
    }
}
