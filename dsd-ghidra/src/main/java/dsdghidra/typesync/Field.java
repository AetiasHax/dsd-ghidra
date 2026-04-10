package dsdghidra.typesync;

import org.jetbrains.annotations.Nullable;

import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.*;

public record Field(
    @Nullable String name, TypeKind kind, boolean isConstant, boolean isVolatile, byte bitFieldWidth
)
{
    /**
     * @param root Data to parse.
     * @return a {@link Field}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Field parse(Map<String, Object> root) throws Types.ParseException {
        String name;
        try {
            Object nameNode = expectKey(root, "name");
            name = nameNode == null ? null : expectText(nameNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for field", e);
        }

        Object kindNode;
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
            Object bitFieldWidthNode = expectKey(root, "bit_field_width");
            bitFieldWidth = bitFieldWidthNode == null ? 0 : expectByte(bitFieldWidthNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse bit field width for field `" + name + "`",
                e
            );
        }

        return new Field(name, kind, isConstant, isVolatile, bitFieldWidth);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        Field field = (Field) object;
        return isConstant == field.isConstant && isVolatile == field.isVolatile && bitFieldWidth == field.bitFieldWidth && Objects.equals(name,
            field.name
        ) && Objects.equals(kind, field.kind);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, kind, isConstant, isVolatile, bitFieldWidth);
    }
}
