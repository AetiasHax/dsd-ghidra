package dsdghidra.util;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import org.jetbrains.annotations.Nullable;

public final class DataTypeUtil {
    public static @Nullable DataType getUndefined4() {
        BuiltInDataTypeManager builtInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        return builtInDataTypeManager.getDataType("/undefined4");
    }
}
