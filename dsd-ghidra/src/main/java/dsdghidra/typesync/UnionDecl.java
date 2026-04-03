package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.Nullable;

import static dsdghidra.typesync.TypesyncUtil.*;

public record UnionDecl(@Nullable String name, Field[] fields, long size, long alignment)
    implements TypeKind
{
    /**
     * @param root Data to parse.
     * @return A {@link UnionDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static UnionDecl parse(JsonNode root) throws Types.ParseException {
        String name;
        try {
            JsonNode nameNode = expectKey(root, "name");
            name = nameNode.isNull() ? null : expectText(nameNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for union", e);
        }

        JsonNode fieldsNode;
        try {
            fieldsNode = expectArray(expectKey(root, "fields"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get fields for union `" + name + "`", e);
        }

        Field[] fields = new Field[fieldsNode.size()];
        int i = 0;
        for (JsonNode constantNode : fieldsNode) {
            try {
                fields[i++] = Field.parse(constantNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse field for union `" + name + "`", e);
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size for union `" + name + "`", e);
        }
        long alignment;
        try {
            alignment = expectLong(expectKey(root, "alignment"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse alignment for union `" + name + "`", e);
        }

        return new UnionDecl(name, fields, size, alignment);
    }
}
