package dsdghidra.util;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class DsdError {
    public final @NotNull Memory memory;

    public DsdError() {
        this.memory = new Memory(8);
        this.memory.setPointer(0, Pointer.NULL);
    }

    public @Nullable String getString() {
        Pointer pointer = memory.getPointer(0);
        if (pointer == null) {
            return null;
        }
        return pointer.getString(0);
    }
}
