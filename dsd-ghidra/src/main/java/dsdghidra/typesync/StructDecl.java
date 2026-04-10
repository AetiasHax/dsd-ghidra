package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.*;

public record StructDecl(
    @Nullable TypePath path,
    TypePath[] baseTypes,
    StructField[] fields,
    long size,
    long alignment,
    boolean isVirtual
) implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        if (path == null) {
            throw new Types.NoNameException("Struct has no path");
        }
        return path.toString();
    }

    /**
     * @param root Data to parse.
     * @return a {@link StructDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static StructDecl parse(Map<String, Object> root) throws Types.ParseException {
        TypePath path;
        try {
            Object nameNode = expectKey(root, "path");
            path = nameNode == null ? null : TypePath.parse(expectMap(nameNode));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for struct", e);
        }

        List<Object> baseTypesNode;
        try {
            baseTypesNode = expectArray(expectKey(root, "base_types"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get base types array for struct `" + path + "`",
                e
            );
        }

        TypePath[] baseTypes = new TypePath[baseTypesNode.size()];
        int i = 0;
        for (Object baseTypeNode : baseTypesNode) {
            try {
                baseTypes[i++] = TypePath.parse(expectMap(baseTypeNode));
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse base type path at index " + i + " for struct `" + path + "`");
            }
        }

        List<Object> fieldsNode;
        try {
            fieldsNode = expectArray(expectKey(root, "fields"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get fields array for struct `" + path + "`",
                e
            );
        }

        StructField[] fields = new StructField[fieldsNode.size()];
        i = 0;
        for (Object fieldNode : fieldsNode) {
            try {
                fields[i++] = StructField.parse(expectMap(fieldNode));
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse struct field at index " + i + " for struct `" + path + "`",
                    e
                );
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size for struct `" + path + "`", e);
        }

        long alignment;
        try {
            alignment = expectLong(expectKey(root, "alignment"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse alignment for struct `" + path + "`",
                e
            );
        }

        boolean isVirtual;
        try {
            isVirtual = expectBool(expectKey(root, "is_virtual"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `is_virtual` for struct `" + path + "`",
                e
            );
        }

        return new StructDecl(path, baseTypes, fields, size, alignment, isVirtual);
    }

    public boolean isEmpty(Types types) {
        if (fields.length > 0) {
            return false;
        }
        for (TypePath baseTypePath : baseTypes) {
            TypeKind baseType = types.get(baseTypePath);
            if (baseType instanceof StructDecl base && !base.isEmpty(types)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        StructDecl that = (StructDecl) object;
        return size == that.size && alignment == that.alignment && isVirtual == that.isVirtual && Objects.equals(path,
            that.path
        ) && Objects.deepEquals(baseTypes, that.baseTypes) && Objects.deepEquals(
            fields,
            that.fields
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            path,
            Arrays.hashCode(baseTypes),
            Arrays.hashCode(fields),
            size,
            alignment,
            isVirtual
        );
    }
}
