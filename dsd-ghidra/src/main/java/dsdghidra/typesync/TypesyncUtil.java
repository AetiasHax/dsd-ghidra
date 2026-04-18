package dsdghidra.typesync;

import java.util.Collections;
import java.util.List;
import java.util.Map;

final class TypesyncUtil {
    private TypesyncUtil() {
    }

    /**
     * @param root Node to get the value from.
     * @param key  Name of key mapped to the desired value.
     * @return an {@link Object}.
     * @throws Types.ParseException if the key did not exist in `root`.
     */
    static Object expectKey(Map<String, Object> root, String key) throws Types.ParseException {
        if (!root.containsKey(key)) {
            throw new Types.ParseException("Expected key `" + key + "`");
        }
        return root.get(key);
    }

    /**
     * @param node Node to check if it's a string.
     * @return a non-empty {@link String}.
     * @throws Types.ParseException if `node` is not a string or an empty string.
     */
    static String expectText(Object node) throws Types.ParseException {
        if (!(node instanceof String)) {
            throw new Types.ParseException("Expected node to be a non-empty string");
        }
        return (String) node;
    }

    /**
     * @param node Node to check if it's a Boolean.
     * @return a `boolean`.
     * @throws Types.ParseException if `node` is not a Boolean.
     */
    static boolean expectBool(Object node) throws Types.ParseException {
        if (!(node instanceof Boolean)) {
            throw new Types.ParseException("Expected node to be a Boolean");
        }
        return (Boolean) node;
    }

    /**
     * @param node Node to check if it's a `long`.
     * @return a `long`.
     * @throws Types.ParseException if `node` is not a `long`.
     */
    static long expectLong(Object node) throws Types.ParseException {
        if (!(node instanceof Number)) {
            throw new Types.ParseException("Expected node to be a long");
        }
        return ((Number) node).longValue();
    }

    /**
     * @param node Node to check if it's a `byte`.
     * @return a `byte`.
     * @throws Types.ParseException if `node` is not a `byte`.
     */
    static byte expectByte(Object node) throws Types.ParseException {
        if (!(node instanceof Number)) {
            throw new Types.ParseException("Expected node to be a byte");
        }
        return ((Number) node).byteValue();
    }

    /**
     * @param root Node to check if it's an array.
     * @return `root`.
     * @throws Types.ParseException if `root` is not an array.
     */
    static List<Object> expectArray(Object root) throws Types.ParseException {
        if (root == null) {
            return Collections.emptyList();
        }
        if (!(root instanceof List)) {
            throw new Types.ParseException("Expected node to be an array");
        }
        return (List<Object>) root;
    }

    /**
     * @param root Node to check if it's a Map.
     * @return `root` as a Map.
     * @throws Types.ParseException if `root` is not a Map.
     */
    static <T> Map<T, Object> expectMap(Object root) throws Types.ParseException {
        if (!(root instanceof Map)) {
            throw new Types.ParseException("Expected node to be an object");
        }
        return (Map<T, Object>) root;
    }
}
