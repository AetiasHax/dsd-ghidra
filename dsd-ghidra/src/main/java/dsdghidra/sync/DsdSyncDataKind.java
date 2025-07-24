package dsdghidra.sync;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum DsdSyncDataKind {
    Any,
    Byte,
    Short,
    Word;

    public static final @NotNull DsdSyncDataKind[] VALUES = DsdSyncDataKind.values();

    public int size() {
        switch (this) {
            case Any -> {
                return 0;
            }
            case Byte -> {
                return 1;
            }
            case Short -> {
                return 2;
            }
            case Word -> {
                return 4;
            }
        }
        return 0;
    }

    public boolean isDefined() {
        return this != DsdSyncDataKind.Any;
    }

    public @Nullable DataType asDataType() {
        BuiltInDataTypeManager dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        switch (this) {
            case Any -> {
                return dataTypeManager.getDataType("/undefined");
            }
            case Byte -> {
                return dataTypeManager.getDataType("/byte");
            }
            case Short -> {
                return dataTypeManager.getDataType("/word");
            }
            case Word -> {
                return dataTypeManager.getDataType("/dword");
            }
        }
        return null;
    }
}
