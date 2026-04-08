package dsdghidra.typesync;

import java.util.Map;

import static dsdghidra.typesync.TypesyncUtil.*;

public record StructField(long offset, Field field) {
    /**
     * @param root Data to parse.
     * @return a {@link StructField}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static StructField parse(Map<String, Object> root) throws Types.ParseException {
        Field field;
        try {
            field = Field.parse(expectMap(expectKey(root, "field")));
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
