package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncModule extends Structure {
    public int base_address;
    public UnsafeList<DsdSyncSection> sections;
    public UnsafeList<DsdSyncDelinkFile> files;

    public DsdSyncModule() {
        super();
    }

    public DsdSyncModule(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("base_address", "sections", "files");
    }

    public @NotNull DsdSyncSection[] getSections() {
        return sections.getArray(new DsdSyncSection[0], DsdSyncSection::new);
    }

    public @NotNull DsdSyncDelinkFile[] getFiles() {
        return files.getArray(new DsdSyncDelinkFile[0], DsdSyncDelinkFile::new);
    }
}
