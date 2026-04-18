package dsdghidra.typesync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import dsdghidra.types.UnsafeU8List;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class TypeSyncOptions extends Structure {
    public UnsafeString project_path;
    public UnsafeList<UnsafeString> includes;
    public UnsafeList<UnsafeString> files;
    public UnsafeU8List languages;
    public boolean short_enums;
    public boolean signed_char;

    public TypeSyncOptions() {
    }

    public TypeSyncOptions(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of(
            "project_path",
            "includes",
            "files",
            "languages",
            "short_enums",
            "signed_char"
        );
    }
}
