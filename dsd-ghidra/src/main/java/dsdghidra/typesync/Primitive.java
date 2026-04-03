package dsdghidra.typesync;

public record Primitive(String ghidraTypeName) implements TypeKind {
    public static final Primitive USIZE = new Primitive("uint");
    public static final Primitive SSIZE = new Primitive("int");
    public static final Primitive U64 = new Primitive("ulonglong");
    public static final Primitive U32 = new Primitive("uint");
    public static final Primitive U16 = new Primitive("ushort");
    public static final Primitive U8 = new Primitive("byte");
    public static final Primitive S64 = new Primitive("longlong");
    public static final Primitive S32 = new Primitive("int");
    public static final Primitive S16 = new Primitive("short");
    public static final Primitive S8 = new Primitive("char");
    public static final Primitive LONG_DOUBLE = new Primitive("longdouble");
    public static final Primitive CHAR16 = new Primitive("wchar16");
    public static final Primitive CHAR32 = new Primitive("wchar32");
    public static final Primitive WCHAR = new Primitive("wchar_t");
    public static final Primitive BOOL = new Primitive("bool");
    public static final Primitive VOID = new Primitive("void");
}
