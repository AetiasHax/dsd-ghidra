//Imports types from a C/C++ codebase into this Ghidra project.
//@author Aetias
//@category dsd
//@keybinding
//@menupath Analysis.Sync DSD
//@toolbar typesync.png

import dialog.typesync.TypeSyncConfigDialog;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import org.jetbrains.annotations.NotNull;

import java.util.*;
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

        this.println(configResult.includes().toString());
        this.println(configResult.excludes().toString());

//        this.printAllTypePaths();
//        this.testTypes();
    }

    private void testTypes() {
        var dword = this.dataTypeManager.getDataType("/dword");
        this.println(dword.toString());

        // Typedef
        var newU32Typedef = new TypedefDataType(CATEGORY_PATH, "u32", dword);
        var u32 = (TypeDef) this.category.addDataType(newU32Typedef, DataTypeConflictHandler.KEEP_HANDLER);

        // Struct
        var newStruct = new StructureDataType(CATEGORY_PATH, "MyTestStruct", 0);
        var struct = (Structure) this.category.addDataType(newStruct, DataTypeConflictHandler.KEEP_HANDLER);

        struct.deleteAll();
        struct.add(u32, "mUnk_00", "");

        this.println(struct.getPathName());

        // Enum
        var newEnumType = new EnumDataType(CATEGORY_PATH, "MyTestEnum", 4);
        var enumType = (Enum) this.category.addDataType(newEnumType, DataTypeConflictHandler.KEEP_HANDLER);

        for (var name : enumType.getNames()) {
            enumType.remove(name);
        }
        enumType.add("FOO", 1);
        enumType.add("BAR", 2);
        enumType.add("BAZ", 6);

        // Union
        var newUnion = new UnionDataType(CATEGORY_PATH, "MyTestUnion");
        var union = (Union) this.category.addDataType(newUnion, DataTypeConflictHandler.KEEP_HANDLER);

        var ordinals = Arrays.stream(union.getComponents()).map(DataTypeComponent::getOrdinal).collect(Collectors.toSet());
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
