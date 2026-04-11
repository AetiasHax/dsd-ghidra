package dsdghidra.types;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class UnsafeU8List extends Structure {
    public Pointer ptr;
    public int len;

    public UnsafeU8List() {
    }

    public UnsafeU8List(byte[] items) {
        if (items.length == 0) {
            this.ptr = null;
            this.len = 0;
            return;
        }

        this.ptr = new Memory(items.length);
        this.ptr.write(0, items, 0, items.length);
        this.len = items.length;
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr", "len");
    }

    public byte[] getArray() {
        if (ptr == null) {
            return new byte[0];
        }
        return ptr.getByteArray(0, len);
    }
}
