package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.expectKey;
import static dsdghidra.typesync.TypesyncUtil.expectLong;

public record Array(TypeKind elementType, long size) implements TypeKind {
    /**
     * @param root Data to parse.
     * @return an {@link Array} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Array parse(JsonNode root) throws Types.ParseException {
        JsonNode elementTypeNode = expectKey(root, "element_type");
        TypeKind elementType;
        try {
            elementType = TypeKind.parse(elementTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse element type of array", e);
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size of array", e);
        }

        return new Array(elementType, size);
    }
}
