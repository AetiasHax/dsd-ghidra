package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class UnsafeU32List extends Structure {
    public Pointer ptr;
    public int len;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr", "len");
    }

    public int[] getArray() {
        if (ptr == null) {
            return new int[0];
        }
        return ptr.getIntArray(0, len);
    }
}
