package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.expectKey;

public record Pointer(TypeKind pointeeType) implements TypeKind {
    /**
     * @param root Data to parse.
     * @return a {@link Pointer} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Pointer parse(JsonNode root) throws Types.ParseException {
        JsonNode pointeeTypeNode = expectKey(root, "pointee_type");
        TypeKind pointeeType;
        try {
            pointeeType = TypeKind.parse(pointeeTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse pointee type of pointer", e);
        }
        return new Pointer(pointeeType);
    }
}
