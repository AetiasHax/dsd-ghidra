package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.*;

public record Typedef(String name, TypeKind underlyingType, boolean isConstant, boolean isVolatile)
    implements TypeKind
{
    /**
     * @param root Data to parse.
     * @return a {@link Typedef} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Typedef parse(JsonNode root) throws Types.ParseException {
        String name;
        try {
            name = expectText(expectKey(root, "name"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for typedef", e);
        }

        JsonNode underlyingTypeNode = expectKey(root, "underlying_type");
        TypeKind underlyingType;
        try {
            underlyingType = TypeKind.parse(underlyingTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse underlying type of typedef `" + name + "`");
        }

        boolean isConstant;
        try {
            isConstant = expectBool(expectKey(root, "constant"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `isConstant` for typedef `" + name + "`",
                e
            );
        }
        boolean isVolatile;
        try {
            isVolatile = expectBool(expectKey(root, "volatile"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `isVolatile` for typedef `" + name + "`",
                e
            );
        }

        return new Typedef(name, underlyingType, isConstant, isVolatile);
    }
}
