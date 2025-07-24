package dsdghidra.util;

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class DataTypeUtil {
    public static @Nullable DataType getUndefined4() {
        BuiltInDataTypeManager builtInDataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
        return builtInDataTypeManager.getDataType("/undefined4");
    }

    public static @Nullable MutabilitySettingsDefinition getMutabilitySettingsDefinition(DataType dataType) {
        for (SettingsDefinition definition : dataType.getSettingsDefinitions()) {
            if (definition instanceof MutabilitySettingsDefinition) {
                return (MutabilitySettingsDefinition) definition;
            }
        }
        return null;
    }

    public static void setDataMutability(@NotNull Data data, int value) throws DataTypeUtil.Exception {
        DataType dataType = data.getDataType();
        MutabilitySettingsDefinition definition = getMutabilitySettingsDefinition(dataType);
        if (definition == null) {
            throw new DataTypeUtil.Exception(String.format(
                "Failed to set data mutability for %s, mutability settings definition not found",
                data
            ));
        }
        definition.setChoice(data, value);
    }

    public static final class Exception extends java.lang.Exception {
        public Exception(String message) {
            super(message);
        }
    }
}
