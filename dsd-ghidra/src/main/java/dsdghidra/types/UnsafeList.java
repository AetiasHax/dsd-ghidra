package dsdghidra.types;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public class UnsafeList<T extends Structure> extends Structure {
    public Pointer ptr;
    public int len;

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("ptr", "len");
    }

    public UnsafeList() {
    }

    public UnsafeList(UnsafeString[] items) {
        if (items.length == 0) {
            this.ptr = null;
            this.len = 0;
            return;
        }

        UnsafeString[] contiguousArray = (UnsafeString[]) items[0].toArray(items.length);
        for (int i = 0; i < items.length; i++) {
            contiguousArray[i].ptr = items[i].ptr;
            contiguousArray[i].write();
        }
        this.ptr = contiguousArray[0].getPointer();
        this.len = items.length;
    }

    public @NotNull T[] getArray(@NotNull T[] emptyArray, @NotNull Function<Pointer, T> factory) {
        if (ptr == null) {
            return emptyArray;
        }
        T[] array = Arrays.copyOf(emptyArray, len);
        Pointer pointer = ptr;
        for (int i = 0; i < len; i++) {
            array[i] = factory.apply(pointer);
            pointer = pointer.share(array[i].size());
        }
        return array;
    }
}
