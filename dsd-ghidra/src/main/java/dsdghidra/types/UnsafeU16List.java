package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class UnsafeU16List extends Structure {
    public Pointer ptr;
    public int len;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr", "len");
    }

    public short[] getArray() {
        if (ptr == null) {
            return new short[0];
        }
        return ptr.getShortArray(0, len);
    }
}
