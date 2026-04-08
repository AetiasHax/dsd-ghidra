package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

import static dsdghidra.typesync.TypesyncUtil.expectKey;
import static dsdghidra.typesync.TypesyncUtil.expectLong;

public record ArrayType(TypeKind elementType, long size) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Arrays cannot have names");
    }

    /**
     * @param root Data to parse.
     * @return an {@link ArrayType} instance.
     * @throws Types.ParseException if the data is invalid.
     */
    public static ArrayType parse(Map<String, Object> root) throws Types.ParseException {
        Object elementTypeNode = expectKey(root, "element_type");
        TypeKind elementType;
        try {
            elementType = TypeKind.parse(elementTypeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse element type of array", e);
        }

        long size;
        try {
            Object sizeNode = expectKey(root, "size");
            size = sizeNode == null ? -1 : expectLong(sizeNode);
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse size of array", e);
        }

        return new ArrayType(elementType, size);
    }
}
