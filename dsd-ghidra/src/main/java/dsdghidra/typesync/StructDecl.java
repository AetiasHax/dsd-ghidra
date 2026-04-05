package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import static dsdghidra.typesync.TypesyncUtil.*;

public record StructDecl(
    @Nullable String name,
    String[] baseTypes,
    StructField[] fields,
    long size,
    long alignment,
    boolean isClass
) implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        if (name == null) {
            throw new Types.NoNameException("Struct has no name");
        }
        return name;
    }

    /**
     * @param root Data to parse.
     * @return a {@link StructDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static StructDecl parse(JsonNode root) throws Types.ParseException {
        String name;
        try {
            JsonNode nameNode = expectKey(root, "name");
            name = nameNode.isNull() ? null : expectText(nameNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for struct", e);
        }

        JsonNode baseTypesNode;
        try {
            baseTypesNode = expectArray(expectKey(root, "base_types"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get base types array for struct `" + name + "`",
                e
            );
        }

        String[] baseTypes = new String[baseTypesNode.size()];
        int i = 0;
        for (JsonNode baseTypeNode : baseTypesNode) {
            try {
                baseTypes[i++] = expectText(baseTypeNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse base type at index " + i + " for struct `" + name + "`");
            }
        }

        JsonNode fieldsNode;
        try {
            fieldsNode = expectArray(expectKey(root, "fields"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get fields array for struct `" + name + "`",
                e
            );
        }

        StructField[] fields = new StructField[fieldsNode.size()];
        i = 0;
        for (JsonNode fieldNode : fieldsNode) {
            try {
                fields[i++] = StructField.parse(fieldNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse struct field at index " + i + " for struct `" + name + "`",
                    e
                );
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size for struct `" + name + "`", e);
        }

        long alignment;
        try {
            alignment = expectLong(expectKey(root, "alignment"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse alignment for struct `" + name + "`",
                e
            );
        }

        boolean isClass;
        try {
            isClass = expectBool(expectKey(root, "is_class"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `is_class` for struct `" + name + "`",
                e
            );
        }

        return new StructDecl(name, baseTypes, fields, size, alignment, isClass);
    }
}
