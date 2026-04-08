package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Map;

import static dsdghidra.typesync.TypesyncUtil.*;

public record UnionDecl(@Nullable TypePath path, Field[] fields, long size, long alignment)
    implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        if (path == null) {
            throw new Types.NoNameException("Union has no path");
        }
        return path.toString();
    }

    /**
     * @param root Data to parse.
     * @return A {@link UnionDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static UnionDecl parse(Map<String, Object> root) throws Types.ParseException {
        TypePath path;
        try {
            Object nameNode = expectKey(root, "path");
            path = nameNode == null ? null : TypePath.parse(expectMap(nameNode));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for union", e);
        }

        List<Object> fieldsNode;
        try {
            fieldsNode = expectArray(expectKey(root, "fields"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get fields for union `" + path + "`", e);
        }

        Field[] fields = new Field[fieldsNode.size()];
        int i = 0;
        for (Object constantNode : fieldsNode) {
            try {
                fields[i++] = Field.parse(expectMap(constantNode));
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse field for union `" + path + "`", e);
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size for union `" + path + "`", e);
        }
        long alignment;
        try {
            alignment = expectLong(expectKey(root, "alignment"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse alignment for union `" + path + "`", e);
        }

        return new UnionDecl(path, fields, size, alignment);
    }
}
