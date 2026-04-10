package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Map;
import java.util.Objects;

public record NamedType(TypePath typePath) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Named types do not have names themselves");
    }

    /**
     * @param root Data to parse.
     * @return a {@link NamedType} instance.
     * @throws Types.ParseException if the data is not a string or an empty string.
     */
    public static NamedType parse(Map<String, Object> root) throws Types.ParseException {
        TypePath typePath;
        try {
            typePath = TypePath.parse(root);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for named type", e);
        }
        return new NamedType(typePath);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        NamedType namedType = (NamedType) object;
        return Objects.equals(typePath, namedType.typePath);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(typePath);
    }
}
