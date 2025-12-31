//Imports types from a C/C++ codebase into this Ghidra project.
//@author Aetias
//@category dsd
//@keybinding
//@menupath Analysis.Sync DSD
//@toolbar typesync.png

import dialog.typesync.TypeSyncConfigDialog;
import dsdghidra.DsdGhidra;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import dsdghidra.typesync.TypeSyncOptions;
import dsdghidra.util.DsdError;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public class SyncTypes extends DsdGhidraScript {
    private static final CategoryPath CATEGORY_PATH = CategoryPath.ROOT.extend("typesync");

    private DataTypeManager dataTypeManager;
    private Category category;

    @Override
    protected void run() throws Exception {
        this.dataTypeManager = this.currentProgram.getDataTypeManager();
        this.category = this.dataTypeManager.createCategory(CATEGORY_PATH);

        this.loadProperties();

        var configDialog = new TypeSyncConfigDialog(this.properties);
        var configResult = configDialog.getResult();
        if (configResult == null) {
            return;
        }

        this.saveProperties();

        TypeSyncOptions options = new TypeSyncOptions();
        UnsafeString[] includeStrings = (UnsafeString[]) configResult
            .includes()
            .stream()
            .map(file -> new UnsafeString(file.toString()))
            .toArray(UnsafeString[]::new);
        options.includes = new UnsafeList<>(includeStrings);
        UnsafeString[] excludeStrings = (UnsafeString[]) configResult
            .excludes()
            .stream()
            .map(file -> new UnsafeString(file.toString()))
            .toArray(UnsafeString[]::new);
        options.excludes = new UnsafeList<>(excludeStrings);
        options.short_enums = configResult.shortEnums();
        options.signed_char = configResult.signedChar();
        UnsafeString data = new UnsafeString();
        DsdError dsdError = new DsdError();
        if (!DsdGhidra.INSTANCE.get_type_sync_data(options, data, dsdError.memory)) {
            String errorMessage = "Failed to get type sync data from dsd-ghidra:\n\n" + dsdError.getString() + "\n";
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
            throw new IOException(errorMessage);
        }

        try {
            this.doSync(data);
        } finally {
            if (!DsdGhidra.INSTANCE.free_type_sync_data(data, dsdError.memory)) {
                this.printerr("Failed to free type sync data from dsd-ghidra:\n" + dsdError.getString());
            }
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
        }

        //        this.printAllTypePaths();
        //        this.testTypes();
    }

    private void doSync(UnsafeString data) {
        this.println(data.getString());
    }

    private void testTypes() {
        var dword = this.dataTypeManager.getDataType("/dword");
        this.println(dword.toString());

        // Typedef
        var newU32Typedef = new TypedefDataType(CATEGORY_PATH, "u32", dword);
        var u32 = (TypeDef) this.category.addDataType(
            newU32Typedef,
            DataTypeConflictHandler.KEEP_HANDLER
        );

        // Struct
        var newStruct = new StructureDataType(CATEGORY_PATH, "MyTestStruct", 0);
        var struct = (Structure) this.category.addDataType(
            newStruct,
            DataTypeConflictHandler.KEEP_HANDLER
        );

        struct.deleteAll();
        struct.add(u32, "mUnk_00", "");

        this.println(struct.getPathName());

        // Enum
        var newEnumType = new EnumDataType(CATEGORY_PATH, "MyTestEnum", 4);
        var enumType = (Enum) this.category.addDataType(
            newEnumType,
            DataTypeConflictHandler.KEEP_HANDLER
        );

        for (var name : enumType.getNames()) {
            enumType.remove(name);
        }
        enumType.add("FOO", 1);
        enumType.add("BAR", 2);
        enumType.add("BAZ", 6);

        // Union
        var newUnion = new UnionDataType(CATEGORY_PATH, "MyTestUnion");
        var union = (Union) this.category.addDataType(
            newUnion,
            DataTypeConflictHandler.KEEP_HANDLER
        );

        var ordinals = Arrays
            .stream(union.getComponents())
            .map(DataTypeComponent::getOrdinal)
            .collect(Collectors.toSet());
        union.delete(ordinals);

        union.add(struct);
        union.add(u32, "intValue", "");
        union.add(enumType, "enumThing", "");
    }

    private void printAllTypePaths() {
        for (var type : this.getCustomDataTypes()) {
            this.println(type.getDataTypePath().toString());
        }
    }

    private @NotNull List<DataType> getCustomDataTypes() {
        List<DataType> dataTypeList = new ArrayList<>();
        this.dataTypeManager.getAllDataTypes(dataTypeList);

        dataTypeList.removeIf(type -> type instanceof BuiltInDataType || type instanceof Array || type instanceof Pointer);
        return Collections.unmodifiableList(dataTypeList);
    }
}
