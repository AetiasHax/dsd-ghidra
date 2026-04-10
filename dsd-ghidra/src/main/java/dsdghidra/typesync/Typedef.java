package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.*;

public record Typedef(
    TypePath path, TypeKind underlyingType, boolean isConstant, boolean isVolatile
) implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        return path.toString();
    }

    /**
     * @param root Data to parse.
     * @return a {@link Typedef} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Typedef parse(Map<String, Object> root) throws Types.ParseException {
        TypePath path;
        try {
            path = TypePath.parse(expectMap(expectKey(root, "path")));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for typedef", e);
        }

        Object underlyingTypeNode = expectKey(root, "underlying_type");
        TypeKind underlyingType;
        try {
            underlyingType = TypeKind.parse(underlyingTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse underlying type of typedef `" + path + "`");
        }

        boolean isConstant;
        try {
            isConstant = expectBool(expectKey(root, "constant"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `isConstant` for typedef `" + path + "`",
                e
            );
        }
        boolean isVolatile;
        try {
            isVolatile = expectBool(expectKey(root, "volatile"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse `isVolatile` for typedef `" + path + "`",
                e
            );
        }

        return new Typedef(path, underlyingType, isConstant, isVolatile);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        Typedef typedef = (Typedef) object;
        return isConstant == typedef.isConstant && isVolatile == typedef.isVolatile && Objects.equals(path,
            typedef.path
        ) && Objects.equals(underlyingType, typedef.underlyingType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, underlyingType, isConstant, isVolatile);
    }
}
