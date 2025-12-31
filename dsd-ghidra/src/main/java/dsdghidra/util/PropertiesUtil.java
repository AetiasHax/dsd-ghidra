package dsdghidra.util;

import java.io.File;
import java.util.*;

public final class PropertiesUtil {
    private PropertiesUtil() {
    }

    public static void setList(Properties properties, String key, Collection<?> objects) {
        var escapedStrings = objects
            .stream()
            .map(object -> {
                var string = object.toString();
                if (string.contains(",")) {
                    return '"' + object.toString().replace("\"", "\\\"") + '"';
                } else {
                    return string;
                }
            })
            .toList();
        var joinedString = String.join(",", escapedStrings);
        properties.setProperty(key, joinedString);
    }

    public static List<String> getStrings(Properties properties, String key) {
        var joinedString = properties.getProperty(key);
        if (joinedString == null) {
            return List.of();
        }
        var escapedStrings = joinedString.split(",");
        var strings = new ArrayList<String>();
        for (var escapedString : escapedStrings) {
            if (escapedString.isEmpty()) {
                continue;
            }
            int length = escapedString.length();
            var string = escapedString;
            if (string.charAt(0) == '"' && string.charAt(length - 1) == '"') {
                string = escapedString.substring(1, length - 1).replace("\\\"", "\"");
            }
            strings.add(string);
        }
        return strings;
    }

    public static List<File> getFiles(Properties properties, String key) {
        var pathStrings = getStrings(properties, key);
        return pathStrings.stream().map(File::new).toList();
    }

    public static void setBoolean(Properties properties, String key, boolean value) {
        if (value) {
            properties.setProperty(key, "true");
        } else {
            properties.setProperty(key, "false");
        }
    }

    public static boolean getBoolean(Properties properties, String key, boolean defaultValue) {
        String property = properties.getProperty(key);
        if (property == null) {
            return defaultValue;
        }
        return switch (property) {
            case "true", "1" -> true;
            default -> false;
        };
    }
}
