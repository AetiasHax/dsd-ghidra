package dsdghidra.typesync;

import com.fasterxml.jackson.databind.JsonNode;

final class TypesyncUtil {
    private TypesyncUtil() {
    }

    /**
     * @param root Node to get the value from.
     * @param key  Name of key mapped to the desired value.
     * @return a non-null {@link JsonNode}.
     * @throws Types.ParseException if the key did not exist in `root`.
     */
    static JsonNode expectKey(JsonNode root, String key) throws Types.ParseException {
        JsonNode node = root.get(key);
        if (node == null) {
            throw new Types.ParseException("Expected key `" + key + "`");
        }
        return node;
    }

    /**
     * @param node Node to check if it's a string.
     * @return a non-empty {@link String}.
     * @throws Types.ParseException if `node` is not a string or an empty string.
     */
    static String expectText(JsonNode node) throws Types.ParseException {
        String text = node.asText();
        if (text.isEmpty()) {
            throw new Types.ParseException("Expected node to be a non-empty string");
        }
        return text;
    }

    /**
     * @param node Node to check if it's a Boolean.
     * @return a `boolean`.
     * @throws Types.ParseException if `node` is not a Boolean.
     */
    static boolean expectBool(JsonNode node) throws Types.ParseException {
        if (!node.isBoolean()) {
            throw new Types.ParseException("Expected node to be a Boolean");
        }
        return node.asBoolean();
    }

    /**
     * @param node Node to check if it's a `long`.
     * @return a `long`.
     * @throws Types.ParseException if `node` is not a `long`.
     */
    static long expectLong(JsonNode node) throws Types.ParseException {
        if (!node.canConvertToLong()) {
            throw new Types.ParseException("Expected node to be a long");
        }
        return node.asLong();
    }

    /**
     * @param node Node to check if it's a `byte`.
     * @return a `byte`.
     * @throws Types.ParseException if `node` is not a `byte`.
     */
    static byte expectByte(JsonNode node) throws Types.ParseException {
        int value = node.asInt();
        if (!node.canConvertToInt() && value < 256) {
            throw new Types.ParseException("Expected node to be a byte");
        }
        return (byte) value;
    }

    /**
     * @param root Node to check if it's an array.
     * @return `root`.
     * @throws Types.ParseException if `root` is not an array.
     */
    static JsonNode expectArray(JsonNode root) throws Types.ParseException {
        if (!root.isArray()) {
            throw new Types.ParseException("Expected node to be an array");
        }
        return root;
    }

    /**
     * @param root Node to check if it's an object.
     * @return `root`.
     * @throws Types.ParseException if `root` is not an object.
     */
    static JsonNode expectObject(JsonNode root) throws Types.ParseException {
        if (!root.isObject()) {
            throw new Types.ParseException("Expected node to be an object");
        }
        return root;
    }
}
