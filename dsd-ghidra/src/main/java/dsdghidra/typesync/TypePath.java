package dsdghidra.typesync;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static dsdghidra.typesync.TypesyncUtil.*;

public record TypePath(String[] namespaces, String name, TypeKind[] templateArguments) {
    /**
     * @param root Data to parse.
     * @return a {@link TypePath}.
     * @throws Types.ParseException if the data is invalid.
     */
    static TypePath parse(Map<String, Object> root) throws Types.ParseException {
        String name;
        try {
            name = expectText(expectKey(root, "name"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get path for type path", e);
        }

        List<Object> namespacesNode;
        try {
            namespacesNode = expectArray(expectKey(root, "namespaces"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException("Failed to get namespaces for type path to " + name, e);
        }
        String[] namespaces = new String[namespacesNode.size()];
        int i = 0;
        for (Object namespaceNode : namespacesNode) {
            try {
                namespaces[i++] = expectText(namespaceNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse namespace at index " + i + " for type path to " + name,
                    e
                );
            }
        }

        List<Object> templateArgumentsNode;
        try {
            templateArgumentsNode = expectArray(expectKey(root, "template_arguments"));
        } catch (Types.ParseException e) {
            throw new Types.ParseException(
                "Failed to get template arguments for type path to " + name,
                e
            );
        }
        TypeKind[] templateArguments = new TypeKind[templateArgumentsNode.size()];
        i = 0;
        for (Object templateArgumentNode : templateArgumentsNode) {
            try {
                templateArguments[i++] = TypeKind.parse(templateArgumentNode);
            } catch (Types.ParseException e) {
                throw new Types.ParseException(
                    "Failed to parse template argument at index " + i + " for type path to " + name,
                    e
                );
            }
        }

        return new TypePath(namespaces, name, templateArguments);
    }

    @Override
    public @NotNull String toString() {
        StringBuilder sb = new StringBuilder();
        for (String namespace : namespaces) {
            sb.append(namespace);
            sb.append("::");
        }
        sb.append(name);
        if (templateArguments.length > 0) {
            sb.append('<');
            for (int i = 0; i < templateArguments.length; ++i) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(templateArguments[i].getDisplayName());
            }
            sb.append('>');
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object object) {
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        TypePath path = (TypePath) object;
        return Objects.equals(name, path.name) && Objects.deepEquals(
            namespaces,
            path.namespaces
        ) && Objects.deepEquals(
            templateArguments,
            path.templateArguments
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(namespaces), name, Arrays.hashCode(templateArguments));
    }
}
