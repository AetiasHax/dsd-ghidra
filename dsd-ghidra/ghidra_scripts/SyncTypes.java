//Imports types from a C/C++ codebase into this Ghidra project.
//@author Aetias
//@category dsd
//@keybinding
//@menupath Analysis.Sync DSD
//@toolbar typesync.png

import dialog.DebugMessageDialog;
import dialog.typesync.TypeSyncConfigDialog;
import dsdghidra.DsdGhidra;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import dsdghidra.typesync.*;
import dsdghidra.typesync.PointerType;
import dsdghidra.util.DsdError;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public class SyncTypes extends DsdGhidraScript {
    private static final CategoryPath CATEGORY_PATH = CategoryPath.ROOT.extend("typesync");
    private static final CategoryPath TEMP_CATEGORY_PATH = CategoryPath.ROOT.extend("typesync_temp");

    private DataTypeManager dataTypeManager;
    private Category category;
    private Category tempCategory;

    private List<String> updatingTypes;
    private Map<String, @NotNull DataType> updatedTypes;
    private boolean dryRun;
    private DataTypeConflictHandler dataTypeConflictHandler;
    private Types types;
    private int anonymousTypeCount;

    @Override
    protected void run() throws Exception {
        this.dataTypeManager = this.currentProgram.getDataTypeManager();
        this.category = this.dataTypeManager.createCategory(CATEGORY_PATH);

        Category prevTempCategory = this.dataTypeManager.getCategory(TEMP_CATEGORY_PATH);
        if (prevTempCategory != null) {
            prevTempCategory.getParent().removeCategory(prevTempCategory.getName(), this.monitor);
        }
        this.tempCategory = this.dataTypeManager.createCategory(TEMP_CATEGORY_PATH);

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
        String typeDataYaml = data.getString();
        if (configResult.dumpYaml()) {
            new DebugMessageDialog("Type YAML dump", typeDataYaml).show();
        }

        this.dryRun = configResult.dryRun();

        try {
            this.doSync(typeDataYaml);
        } finally {
            if (!DsdGhidra.INSTANCE.free_type_sync_data(data, dsdError.memory)) {
                this.printerr("Failed to free type sync data from dsd-ghidra:\n" + dsdError.getString());
            }
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
        }

        //        this.printAllTypePaths();
        //        this.testTypes();
    }

    private void doSync(String yaml) throws Exception {
        this.types = Types.parseYaml(yaml);

        //        try (var writer = new FileWriter("/home/aetias/typesync.yaml")) {
        //            writer.write(yaml);
        //        } catch (IOException e) {
        //            throw new RuntimeException(e);
        //        }

        this.updatingTypes = new ArrayList<>();
        this.updatedTypes = new HashMap<>();
        this.anonymousTypeCount = 0;

        for (var entry : types) {
            TypePath name = entry.getKey();
            TypeKind type = entry.getValue();
            this.updateType(type);
        }

        this.updatedTypes = null;
        this.updatingTypes = null;
        this.types = null;
    }

    private @NotNull DataType updateType(@NotNull TypeKind type) throws Exception {
        String name;
        try {
            name = type.getName();
        } catch (Types.NoNameException e) {
            name = "$anonymous" + anonymousTypeCount;
            anonymousTypeCount += 1;
        }

        if (updatingTypes.contains(name)) {
            throw new Exception("Cycle detected: " + String.join(
                " -> ",
                updatingTypes
            ) + " -> " + name);
        }

        DataType cachedType = updatedTypes.get(name);
        if (cachedType != null) {
            return cachedType;
        }

        updatingTypes.add(name);
        try {
            DataType prevType = this.category.getDataType(name);
            DataType newType = switch (type) {
                case ArrayType arrayType -> addArrayType(arrayType);
                case EnumDecl enumDecl -> addEnumType(enumDecl, name);
                case FunctionType functionType -> addFunctionType(functionType, name);
                case NamedType namedType -> addNamedType(namedType);
                case PointerType pointerType -> addPointerType();
                case StructDecl structDecl -> addStructType(structDecl, name);
                case Typedef typedef -> addTypedef(typedef, name);
                case UnionDecl unionDecl -> addUnionType(unionDecl, name);
                case PrimitiveType primitiveType -> {
                    DataType dataType = this.dataTypeManager.getDataType("/" + primitiveType.ghidraTypeName());
                    if (dataType == null) {
                        throw new Exception("Primitive type not found" + primitiveType.ghidraTypeName());
                    }
                    yield dataType;
                }
            };

            this.updatedTypes.put(name, newType);
            return newType;
        } finally {
            updatingTypes.remove(name);
        }
    }

    private @NotNull DataType addUnionType(UnionDecl type, String name) throws Exception {
        var unionType = (Union) addTemporaryType(new UnionDataType(CATEGORY_PATH, name));
        for (Field field : type.fields()) {
            DataType fieldType = this.updateType(field.kind());
            int bitFieldWidth = field.bitFieldWidth();
            if (bitFieldWidth > 0) {
                unionType.addBitField(fieldType, bitFieldWidth, field.name(), "");
            } else {
                unionType.add(fieldType, field.name(), "");
            }
        }
        return unionType;
    }

    private @NotNull DataType addTypedef(Typedef type, String name) throws Exception {
        DataType underlyingType = this.updateType(type.underlyingType());
        return addTemporaryType(new TypedefDataType(CATEGORY_PATH, name, underlyingType));
    }

    private @NotNull DataType addStructType(StructDecl type, String name) throws Exception {
        var structType = (Structure) addTemporaryType(new StructureDataType(
            CATEGORY_PATH,
            name,
            0
        ));
        TypePath[] baseTypes = type.baseTypes();
        for (int i = 0; i < baseTypes.length; i++) {
            TypePath baseTypePath = baseTypes[i];
            TypeKind baseType = this.types.get(baseTypePath);
            assert baseType != null;
            DataType baseDataType = this.updateType(baseType);
            String fieldName = baseTypes.length == 1 ? "base" : "base" + i;
            // TODO: Add the base type's fields instead of the base type itself, and create
            //       a struct for the vtable
            structType.add(baseDataType, fieldName, "");
        }
        for (StructField field : type.fields()) {
            DataType fieldType = this.updateType(field.field().kind());
            int bitFieldWidth = field.field().bitFieldWidth();
            if (bitFieldWidth > 0) {
                structType.addBitField(fieldType, bitFieldWidth, name, "");
            } else {
                structType.add(fieldType, field.field().name(), "");
            }
        }
        return structType;
    }

    private @NotNull DataType addPointerType() {
        // TODO: Fill in placeholder pointer
        return new PointerDataType();
    }

    private @NotNull DataType addNamedType(NamedType type) throws Exception {
        TypeKind namedType = this.types.get(type.typePath());
        if (namedType == null) {
            throw new Exception("Named type not found: " + type.typePath());
        }
        return this.updateType(namedType);
    }

    private @NotNull DataType addFunctionType(FunctionType type, String name) throws Exception {
        var functionType = (FunctionDefinition) addTemporaryType(new FunctionDefinitionDataType(name));
        DataType returnType = this.updateType(type.returnType());
        functionType.setReturnType(returnType);
        var parameters = type.parameters();
        var arguments = new ParameterDefinitionImpl[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            var paramType = this.updateType(parameters[i]);
            arguments[i] = new ParameterDefinitionImpl("param" + i, paramType, "");
        }
        functionType.setArguments(arguments);
        return functionType;
    }

    private DataType addEnumType(EnumDecl type, String name) {
        int length = (int) type.size();
        var enumType = (Enum) addTemporaryType(new EnumDataType(CATEGORY_PATH, name, length));
        for (var constant : type.constants()) {
            enumType.add(constant.name(), constant.value());
        }
        return enumType;
    }

    private DataType addArrayType(ArrayType type) throws Exception {
        DataType elementType = this.updateType(type.elementType());
        int numElements = (int) type.size();
        if (numElements < 0) {
            // unbounded array, set to length 0
            numElements = 0;
        }
        return addTemporaryType(new ArrayDataType(elementType, numElements));
    }

    private DataType addTemporaryType(DataType dataType) {
        //noinspection unchecked
        return this.tempCategory.addDataType(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private boolean isSameTypePath(DataType a, DataType b) {
        return a.getCategoryPath().equals(b.getCategoryPath()) && a.getName().equals(b.getName());
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
