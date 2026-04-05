package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;

import static dsdghidra.typesync.TypesyncUtil.expectKey;

public record PointerType(TypeKind pointeeType) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Pointer types cannot have names");
    }

    /**
     * @param root Data to parse.
     * @return a {@link PointerType} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static PointerType parse(JsonNode root) throws Types.ParseException {
        JsonNode pointeeTypeNode = expectKey(root, "pointee_type");
        TypeKind pointeeType;
        try {
            pointeeType = TypeKind.parse(pointeeTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse pointee type of pointer", e);
        }
        return new PointerType(pointeeType);
    }
}
