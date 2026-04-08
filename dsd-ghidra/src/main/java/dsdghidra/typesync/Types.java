package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.yaml.snakeyaml.Yaml;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static dsdghidra.typesync.TypesyncUtil.expectMap;

public class Types implements Iterable<Map.Entry<TypePath, TypeKind>> {
    private final Map<TypePath, TypeKind> types;

    public Types() {
        this.types = new HashMap<>();
    }

    public Types(Map<TypePath, TypeKind> types) {
        this.types = types;
    }

    /**
     * @param yamlString YAML string to parse.
     * @return a {@link Types} instance.
     * @throws ParseException if the YAML content is invalid.
     */
    public static Types parseYaml(String yamlString) throws ParseException {
        Yaml yaml = new Yaml();
        var root = expectMap(yaml.load(yamlString));

        Types types = new Types();
        var typesNode = expectMap(root.get("types"));

        for (var entry : typesNode.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();

            TypePath typePath;
            try {
                typePath = TypePath.parse(expectMap(key));
            } catch (ParseException e) {
                throw new ParseException("Failed to parse type path", e);
            }

            TypeKind type;
            try {
                type = TypeKind.parse(value);
            } catch (ParseException e) {
                throw new ParseException("Failed to parse type `" + typePath + "`", e);
            }

            if (!types.addIfAbsent(typePath, type)) {
                throw new ParseException("Duplicate type path `" + typePath + "`");
            }
        }

        return types;
    }

    /**
     * @param path Name of type.
     * @param type Which type it is.
     * @return `true` if added, `false` if another type exists with the given path.
     */
    public boolean addIfAbsent(TypePath path, TypeKind type) {
        if (this.types.containsKey(path)) {
            return false;
        }
        this.types.put(path, type);
        return true;
    }

    public @Nullable TypeKind get(TypePath name) {
        return this.types.get(name);
    }

    @Override
    public @NotNull Iterator<Map.Entry<TypePath, TypeKind>> iterator() {
        return this.types.entrySet().iterator();
    }

    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }

        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class NoNameException extends Exception {
        public NoNameException(String message) {
            super(message);
        }

        public NoNameException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
