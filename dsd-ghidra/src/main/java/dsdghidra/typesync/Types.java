package dsdghidra.typesync;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Types implements Iterable<Map.Entry<String, TypeKind>> {
    private final Map<String, TypeKind> types;

    public Types() {
        this.types = new HashMap<>();
    }

    public Types(Map<String, TypeKind> types) {
        this.types = types;
    }

    /**
     * @param yamlString YAML string to parse.
     * @return a {@link Types} instance.
     * @throws JsonProcessingException if `yamlString` is not valid YAML.
     * @throws ParseException          if the YAML content is invalid.
     */
    public static Types parseYaml(String yamlString)
        throws JsonProcessingException, ParseException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        JsonNode root = mapper.readTree(yamlString);

        Types types = new Types();
        JsonNode typesNode = root.get("types");
        if (typesNode == null) {
            throw new ParseException("Expected `types` field in root");
        }

        for (var it = typesNode.fields(); it.hasNext(); ) {
            var typeEntry = it.next();
            String keyName = typeEntry.getKey();
            JsonNode value = typeEntry.getValue();

            TypeKind type;
            try {
                type = TypeKind.parse(value);
            } catch (ParseException e) {
                throw new ParseException("Failed to parse type `" + keyName + "`", e);
            }

            String name;
            try {
                name = type.getName();
            } catch (NoNameException e) {
                throw new ParseException("Type has no name", e);
            }

            if (!types.addIfAbsent(name, type)) {
                throw new ParseException("Duplicate type name `" + name + "`");
            }
        }

        return types;
    }

    /**
     * @param name Name of type.
     * @param type Which type it is.
     * @return `true` if added, `false` if another type exists with the given name.
     */
    public boolean addIfAbsent(String name, TypeKind type) {
        if (this.types.containsKey(name)) {
            return false;
        }
        this.types.put(name, type);
        return true;
    }

    public @Nullable TypeKind get(String name) {
        return this.types.get(name);
    }

    @Override
    public @NotNull Iterator<Map.Entry<String, TypeKind>> iterator() {
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
