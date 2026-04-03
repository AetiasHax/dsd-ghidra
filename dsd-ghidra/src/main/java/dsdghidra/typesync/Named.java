package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.expectText;

public record Named(String typeName) implements TypeKind {
    /**
     * @param root Data to parse.
     * @return a {@link Named} instance.
     * @throws Types.ParseException if the data is not a string or an empty string.
     */
    public static Named parse(JsonNode root) throws Types.ParseException {
        String typeName;
        try {
            typeName = expectText(root);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for named type", e);
        }
        return new Named(typeName);
    }
}
