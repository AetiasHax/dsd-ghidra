package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncDelinkFile extends Structure {
    public UnsafeString name;
    public UnsafeList<DsdSyncBaseSection> sections;

    public DsdSyncDelinkFile() {
    }

    public DsdSyncDelinkFile(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("name", "sections");
    }

    public @NotNull DsdSyncBaseSection[] getSections() {
        return sections.getArray(new DsdSyncBaseSection[0], DsdSyncBaseSection::new);
    }
}
