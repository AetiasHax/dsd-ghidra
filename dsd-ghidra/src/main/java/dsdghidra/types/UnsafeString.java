package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class UnsafeString extends Structure {
    public Pointer ptr;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr");
    }

    public @NotNull String getString() {
        return this.ptr.getString(0);
    }

    @Override
    public String toString() {
        return getString();
    }
}
