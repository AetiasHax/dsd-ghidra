package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.*;

public record EnumDecl(@Nullable TypePath path, EnumConstant[] constants, long size)
    implements TypeKind
{
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        if (path == null) {
            throw new Types.NoNameException("Enum has no path");
        }
        return path.toString();
    }

    @Override
    public @NotNull String getDisplayName() {
        if (path == null) {
            return "anonymous enum";
        } else {
            return path.toString();
        }
    }

    /**
     * @param root Data to parse.
     * @return an {@link EnumDecl}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static EnumDecl parse(Map<String, Object> root) throws Types.ParseException {
        TypePath path;
        try {
            Object nameNode = expectKey(root, "path");
            path = nameNode == null ? null : TypePath.parse(expectMap(nameNode));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse path for enum", e);
        }

        List<Object> constantsNode;
        try {
            constantsNode = expectArray(expectKey(root, "constants"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get enum constants for enum `" + path + "`",
                e
            );
        }

        EnumConstant[] constants = new EnumConstant[constantsNode.size()];
        int i = 0;
        for (Object constantNode : constantsNode) {
            try {
                constants[i++] = EnumConstant.parse(expectMap(constantNode));
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse enum constant for enum `" + path + "`",
                    e
                );
            }
        }

        long size;
        try {
            size = expectLong(expectKey(root, "size"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size of enum `" + path + "`", e);
        }

        return new EnumDecl(path, constants, size);
    }

    public record EnumConstant(String name, long value) {
        /**
         * @param root Data to parse.
         * @return an {@link EnumConstant}.
         * @throws Types.ParseException if the data is invalid.
         */
        private static EnumConstant parse(Map<String, Object> root) throws Types.ParseException {
            String name;
            try {
                name = expectText(expectKey(root, "name"));
            } catch (Types.ParseException e) {
                throw new Types.ParseException("Failed to parse path for enum constant", e);
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

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        EnumDecl enumDecl = (EnumDecl) object;
        return size == enumDecl.size && Objects.equals(path, enumDecl.path) && Objects.deepEquals(constants,
            enumDecl.constants
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, Arrays.hashCode(constants), size);
    }
}
