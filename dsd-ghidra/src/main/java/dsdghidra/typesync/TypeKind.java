package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;

public sealed interface TypeKind
    permits ArrayType, EnumDecl, FunctionType, NamedType, PointerType, PrimitiveType, StructDecl,
    Typedef, UnionDecl
{
    /**
     * @return The name of this type. It can be null for types which cannot have a name, such as
     * arrays. In those cases a Typedef should be used instead.
     */
    @NotNull String getName() throws Types.NoNameException;

    /**
     * @param root Node containing one key (name of type kind).
     * @return a {@link TypeKind}.
     * @throws Types.ParseException if `root` contains invalid data.
     */
    static TypeKind parse(JsonNode root) throws Types.ParseException {

        String kind;
        JsonNode node = null;
        if (root.isObject()) {
            var typeKindEntries = root.fields();
            var typeKindEntry = typeKindEntries.next();
            if (typeKindEntries.hasNext()) {
                throw new Types.ParseException(
                    "Expected node to have one key representing its type kind");
            }

            kind = typeKindEntry.getKey();
            node = typeKindEntry.getValue();
        } else if (root.isTextual()) {
            kind = root.asText();
        } else {
            throw new Types.ParseException("Expected a string or object");
        }


        return switch (kind) {
            case "USize" -> PrimitiveType.USIZE;
            case "SSize" -> PrimitiveType.SSIZE;
            case "U64" -> PrimitiveType.U64;
            case "U32" -> PrimitiveType.U32;
            case "U16" -> PrimitiveType.U16;
            case "U8" -> PrimitiveType.U8;
            case "S64" -> PrimitiveType.S64;
            case "S32" -> PrimitiveType.S32;
            case "S16" -> PrimitiveType.S16;
            case "S8" -> PrimitiveType.S8;
            case "LongDouble" -> PrimitiveType.LONG_DOUBLE;
            case "Char16" -> PrimitiveType.CHAR16;
            case "Char32" -> PrimitiveType.CHAR32;
            case "WChar" -> PrimitiveType.WCHAR;
            case "Bool" -> PrimitiveType.BOOL;
            case "Void" -> PrimitiveType.VOID;
            case "Reference", "Pointer", "MemberPointer" -> PointerType.parse(node);
            case "Array" -> ArrayType.parse(node);
            case "Function" -> FunctionType.parse(node);
            case "Struct", "Class" -> StructDecl.parse(node);
            case "Union" -> UnionDecl.parse(node);
            case "Enum" -> EnumDecl.parse(node);
            case "Typedef" -> Typedef.parse(node);
            case "Named" -> NamedType.parse(node);
            default -> throw new Types.ParseException("Unknown type kind " + kind);
        };
    }
}
