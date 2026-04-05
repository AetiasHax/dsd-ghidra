package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;

import static dsdghidra.typesync.TypesyncUtil.expectText;

public record NamedType(String typeName) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Named types do not have names themselves");
    }

    /**
     * @param root Data to parse.
     * @return a {@link NamedType} instance.
     * @throws Types.ParseException if the data is not a string or an empty string.
     */
    public static NamedType parse(JsonNode root) throws Types.ParseException {
        String typeName;
        try {
            typeName = expectText(root);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for named type", e);
        }
        return new NamedType(typeName);
    }
}
