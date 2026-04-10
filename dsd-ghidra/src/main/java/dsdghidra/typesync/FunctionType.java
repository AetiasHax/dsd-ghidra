package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.expectArray;
import static dsdghidra.typesync.TypesyncUtil.expectKey;

public record FunctionType(TypeKind returnType, TypeKind[] parameters) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Function types cannot have names");
    }

    @Override
    public @NotNull String getDisplayName() {
        StringBuilder sb = new StringBuilder();
        sb.append(returnType);
        sb.append(" fn(");
        for (int i = 0; i < parameters.length; ++i) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(parameters[i]);
        }
        sb.append(")");
        return sb.toString();
    }

    /**
     * @param root Data to parse.
     * @return a {@link FunctionType}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static FunctionType parse(Map<String, Object> root) throws Types.ParseException {
        TypeKind returnType;
        try {
            returnType = TypeKind.parse(expectKey(root, "return_type"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse return type for function", e);
        }

        List<Object> parametersNode;
        try {
            parametersNode = expectArray(expectKey(root, "parameters"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get parameters array for function", e);
        }

        TypeKind[] parameters = new TypeKind[parametersNode.size()];
        int i = 0;
        for (Object parameterNode : parametersNode) {
            try {
                parameters[i++] = TypeKind.parse(parameterNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse parameter at index " + i + " for function",
                    e
                );
            }
        }

        return new FunctionType(returnType, parameters);
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        FunctionType that = (FunctionType) object;
        return Objects.equals(returnType, that.returnType) && Objects.deepEquals(
            parameters,
            that.parameters
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(returnType, Arrays.hashCode(parameters));
    }
}
