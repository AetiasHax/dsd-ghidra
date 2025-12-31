package dsdghidra.typesync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class TypeSyncOptions extends Structure {
    public UnsafeList<UnsafeString> includes;
    public UnsafeList<UnsafeString> excludes;
    public boolean short_enums;
    public boolean signed_char;

    public TypeSyncOptions() {}

    public TypeSyncOptions(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("includes", "excludes", "short_enums", "signed_char");
    }
}
