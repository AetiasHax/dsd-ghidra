package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public record PrimitiveType(String ghidraTypeName) implements TypeKind {
    public static final PrimitiveType USIZE = new PrimitiveType("uint");
    public static final PrimitiveType SSIZE = new PrimitiveType("int");
    public static final PrimitiveType U64 = new PrimitiveType("ulonglong");
    public static final PrimitiveType U32 = new PrimitiveType("uint");
    public static final PrimitiveType U16 = new PrimitiveType("ushort");
    public static final PrimitiveType U8 = new PrimitiveType("byte");
    public static final PrimitiveType S64 = new PrimitiveType("longlong");
    public static final PrimitiveType S32 = new PrimitiveType("int");
    public static final PrimitiveType S16 = new PrimitiveType("short");
    public static final PrimitiveType S8 = new PrimitiveType("char");
    public static final PrimitiveType LONG_DOUBLE = new PrimitiveType("longdouble");
    public static final PrimitiveType CHAR16 = new PrimitiveType("wchar16");
    public static final PrimitiveType CHAR32 = new PrimitiveType("wchar32");
    public static final PrimitiveType WCHAR = new PrimitiveType("wchar_t");
    public static final PrimitiveType BOOL = new PrimitiveType("bool");
    public static final PrimitiveType VOID = new PrimitiveType("void");

    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Primitive types do not have names themselves");
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        PrimitiveType that = (PrimitiveType) object;
        return Objects.equals(ghidraTypeName, that.ghidraTypeName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(ghidraTypeName);
    }
}
