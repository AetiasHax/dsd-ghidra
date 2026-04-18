package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Map;

import static dsdghidra.typesync.TypesyncUtil.expectMap;

public sealed interface TypeKind
    permits ArrayType, EnumDecl, FunctionType, NamedType, PointerType, PrimitiveType, StructDecl,
    Typedef, UnionDecl
{
    /**
     * @return The path of this type. It can be null for types which cannot have a path, such as
     * arrays. In those cases a Typedef should be used instead.
     */
    @NotNull String getName() throws Types.NoNameException;

    /**
     * @return The display name for this type, used for uniquifying names of specialized template
     * classes. Types which may return null in {@link #getName} may return non-null here.
     */
    @NotNull String getDisplayName();

    /**
     * @param root Node containing one key (path of type kind).
     * @return a {@link TypeKind}.
     * @throws Types.ParseException if `root` contains invalid data.
     */
    static TypeKind parse(Object root) throws Types.ParseException {

        String kind;
        Map<String, Object> node = null;
        if (root instanceof Map) {
            var rootMap = (Map<String, Object>) root;
            if (rootMap.size() != 1) {
                throw new Types.ParseException(
                    "Expected node to have exactly one key representing its type kind");
            }
            var typeKindEntry = rootMap.entrySet().iterator().next();
            kind = typeKindEntry.getKey();
            node = expectMap(typeKindEntry.getValue());
        } else if (root instanceof String) {
            kind = (String) root;
        } else {
            throw new Types.ParseException("Expected a string or object");
        }

        try {

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
                case "Struct", "Class", "TemplateClassSpec" -> StructDecl.parse(node);
                case "Union" -> UnionDecl.parse(node);
                case "Enum" -> EnumDecl.parse(node);
                case "Typedef" -> Typedef.parse(node);
                case "Named" -> NamedType.parse(node);
                case "TemplateParam" ->
                    throw new Types.ParseException("Unexpected template parameter");
                default -> throw new Types.ParseException("Unknown type kind " + kind);
            };
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse " + kind + " type", e);
        }
    }
}
