package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;
import org.jetbrains.annotations.NotNull;

import static dsdghidra.typesync.TypesyncUtil.expectArray;
import static dsdghidra.typesync.TypesyncUtil.expectKey;

public record FunctionType(TypeKind returnType, TypeKind[] parameters) implements TypeKind {
    @Override
    public @NotNull String getName() throws Types.NoNameException {
        throw new Types.NoNameException("Function types cannot have names");
    }

    /**
     * @param root Data to parse.
     * @return a {@link FunctionType}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static FunctionType parse(JsonNode root) throws Types.ParseException {
        TypeKind returnType;
        try {
            returnType = TypeKind.parse(expectKey(root, "return_type"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to parse return type for function", e);
        }

        JsonNode parametersNode;
        try {
            parametersNode = expectArray(expectKey(root, "parameters"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get parameters array for function", e);
        }

        TypeKind[] parameters = new TypeKind[parametersNode.size()];
        int i = 0;
        for (JsonNode parameterNode : parametersNode) {
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
}
