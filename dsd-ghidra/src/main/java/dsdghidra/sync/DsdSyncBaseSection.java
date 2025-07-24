package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.dsd.SectionKind;
import dsdghidra.types.UnsafeString;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncBaseSection extends Structure {
    public UnsafeString name;
    public int start_address;
    public int end_address;
    public byte kind;

    public DsdSyncBaseSection() {
        super();
    }

    public DsdSyncBaseSection(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("name", "start_address", "end_address", "kind");
    }

    public @NotNull SectionKind getKind() {
        return SectionKind.VALUES[kind];
    }

    public boolean isEmpty() {
        return start_address == end_address;
    }
}
