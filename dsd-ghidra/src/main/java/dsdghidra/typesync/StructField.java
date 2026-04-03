package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.expectKey;
import static dsdghidra.typesync.TypesyncUtil.expectLong;

public record StructField(long offset, Field field) {
    /**
     * @param root Data to parse.
     * @return a {@link StructField}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static StructField parse(JsonNode root) throws Types.ParseException {
        Field field;
        try {
            field = Field.parse(root);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse field for struct field", e);
        }

        long offset;
        try {
            offset = expectLong(expectKey(root, "offset"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to parse offset for struct field `" + field.name() + "`",
                e
            );
        }

        return new StructField(offset, field);
    }
}
