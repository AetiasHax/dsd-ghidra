package dsdghidra.types;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class UnsafeString extends Structure {
    public Pointer ptr;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr");
    }

    public UnsafeString() {
    }

    public UnsafeString(String string) {
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        Memory memory = new Memory(bytes.length + 1);
        memory.write(0, bytes, 0, bytes.length);
        memory.setByte(bytes.length, (byte) 0);
        this.ptr = memory;

        allocateMemory();
        write();
    }

    public @NotNull String getString() {
        return this.ptr.getString(0);
    }

    @Override
    public String toString() {
        return getString();
    }
}
