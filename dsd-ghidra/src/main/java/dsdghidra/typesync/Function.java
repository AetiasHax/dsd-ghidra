package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

import static dsdghidra.typesync.TypesyncUtil.expectArray;
import static dsdghidra.typesync.TypesyncUtil.expectKey;

public record Function(TypeKind returnType, TypeKind[] parameters) implements TypeKind {
    /**
     * @param root Data to parse.
     * @return a {@link Function}.
     * @throws Types.ParseException if the data is invalid.
     */
    public static Function parse(JsonNode root) throws Types.ParseException {
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

        return new Function(returnType, parameters);
    }
}
