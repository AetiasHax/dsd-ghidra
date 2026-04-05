package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.Nullable;

import static dsdghidra.typesync.TypesyncUtil.*;

public record Field(
    @Nullable String name, TypeKind kind, boolean isConstant, boolean isVolatile, byte bitFieldWidth
)
{
    public static Field parse(JsonNode root) throws Types.ParseException {
        JsonNode nameNode = expectKey(root, "name");
        String name;
        try {
            name = nameNode.isNull() ? null : expectText(nameNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for field", e);
        }

        JsonNode kindNode;
        try {
            kindNode = expectKey(root, "kind");
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse `kind` for field `" + name + "`", e);
        }

        TypeKind kind;
        try {
            kind = TypeKind.parse(kindNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse type of field `" + name + "`", e);
        }

        boolean isConstant;
        try {
            isConstant = expectBool(expectKey(root, "constant"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `constant` for field `" + name + "`",
                e
            );
        }

        boolean isVolatile;
        try {
            isVolatile = expectBool(expectKey(root, "volatile"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `volatile` for field `" + name + "`",
                e
            );
        }

        byte bitFieldWidth;
        try {
            JsonNode bitFieldWidthNode = expectKey(root, "bit_field_width");
            bitFieldWidth = bitFieldWidthNode.isNull() ? 0 : expectByte(bitFieldWidthNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse bit field width for field `" + name + "`",
                e
            );
        }

        return new Field(name, kind, isConstant, isVolatile, bitFieldWidth);
    }
}
