package dsdghidra.typesync;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.util.HashMap;
import java.util.Map;

public class Types {
    private Map<String, TypeKind> types;

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
            String name = typeEntry.getKey();
            JsonNode value = typeEntry.getValue();

            TypeKind type;
            try {
                type = TypeKind.parse(value);
            } catch (ParseException e) {
                throw new ParseException("Failed to parse type `" + name + "`", e);
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
        return this.types.putIfAbsent(name, type) == type;
    }

    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }

        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
