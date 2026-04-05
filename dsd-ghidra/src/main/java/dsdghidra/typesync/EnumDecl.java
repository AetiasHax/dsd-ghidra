package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import static dsdghidra.typesync.TypesyncUtil.*;

public record EnumDecl(@Nullable String name, EnumConstant[] constants, long size)
    implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        if (name == null) {
            throw new Types.NoNameException("Enum has no name");
        }
        return name;
    }

    /**
     * @param root Data to parse.
     * @return an {@link EnumDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static EnumDecl parse(JsonNode root) throws Types.ParseException {
        String name;
        try {
            JsonNode nameNode = expectKey(root, "name");
            name = nameNode.isNull() ? null : expectText(nameNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse name for enum", e);
        }

        JsonNode constantsNode;
        try {
            constantsNode = expectArray(expectKey(root, "constants"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get enum constants for enum `" + name + "`",
                e
            );
        }

        EnumConstant[] constants = new EnumConstant[constantsNode.size()];
        int i = 0;
        for (JsonNode constantNode : constantsNode) {
            try {
                constants[i++] = EnumConstant.parse(constantNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse enum constant for enum `" + name + "`",
                    e
                );
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size of enum `" + name + "`", e);
        }

        return new EnumDecl(name, constants, size);
    }

    public record EnumConstant(String name, long value) {
        /**
         * @param root Data to parse.
         * @return an {@link EnumConstant}.
         * @throws Types.ParseException if the data is invalid.
         */
        private static EnumConstant parse(JsonNode root) throws Types.ParseException {
            String name;
            try {
                name = expectText(expectKey(root, "name"));
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse name for enum constant", e);
            }

            long value;
            try {
                value = expectLong(expectKey(root, "value"));
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse value for enum constant `" + name + "`",
                    e
                );
            }

            return new EnumConstant(name, value);
        }
    }
}
