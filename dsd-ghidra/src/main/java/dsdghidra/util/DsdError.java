package dsdghidra.util;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

public class DsdError {
    public Memory memory;

    public DsdError() {
        this.memory = new Memory(8);
        this.memory.setPointer(0, Pointer.NULL);
    }

    public String getString() {
        Pointer pointer = memory.getPointer(0);
        if (pointer == null) {
            return null;
        }
        return pointer.getString(0);
    }
}
