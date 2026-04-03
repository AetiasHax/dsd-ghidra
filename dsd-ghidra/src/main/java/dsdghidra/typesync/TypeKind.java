package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

public sealed interface TypeKind
    permits Array, EnumDecl, Function, Named, Pointer, Primitive, StructDecl, Typedef, UnionDecl
{
    /**
     * @param root Node containing one key (name of type kind).
     * @return a {@link TypeKind}.
     * @throws Types.ParseException if `root` contains invalid data.
     */
    static TypeKind parse(JsonNode root) throws Types.ParseException {
        var typeKindEntries = root.fields();
        var typeKindEntry = typeKindEntries.next();
        if (typeKindEntries.hasNext()) {
            throw new Types.ParseException(
                "Expected node to have one key representing its type kind");
        }

        var kind = typeKindEntry.getKey();
        var node = typeKindEntry.getValue();

        return switch (kind) {
            case "USize" -> Primitive.USIZE;
            case "SSize" -> Primitive.SSIZE;
            case "U64" -> Primitive.U64;
            case "U32" -> Primitive.U32;
            case "U16" -> Primitive.U16;
            case "U8" -> Primitive.U8;
            case "S64" -> Primitive.S64;
            case "S32" -> Primitive.S32;
            case "S16" -> Primitive.S16;
            case "S8" -> Primitive.S8;
            case "LongDouble" -> Primitive.LONG_DOUBLE;
            case "Char16" -> Primitive.CHAR16;
            case "Char32" -> Primitive.CHAR32;
            case "WChar" -> Primitive.WCHAR;
            case "Bool" -> Primitive.BOOL;
            case "Void" -> Primitive.VOID;
            case "Reference", "Pointer", "MemberPointer" -> Pointer.parse(node);
            case "Array" -> Array.parse(node);
            case "Function" -> Function.parse(node);
            case "Struct", "Class" -> StructDecl.parse(node);
            case "Union" -> UnionDecl.parse(node);
            case "Enum" -> EnumDecl.parse(node);
            case "Typedef" -> Typedef.parse(node);
            case "Named" -> Named.parse(node);
            default -> throw new Types.ParseException("Unknown type kind " + kind);
        };
    }
}
