package dsdghidra.util;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

public final class PropertiesUtil {
    private PropertiesUtil() {
    }

    public static void setList(Properties properties, String key, Collection<?> objects) {
        var escapedStrings = objects.stream().map(object -> {
            var string = object.toString();
            if (string.contains(",")) {
                return '"' + object.toString().replace("\"", "\\\"") + '"';
            } else {
                return string;
            }
        }).toList();
        var joinedString = String.join(",", escapedStrings);
        properties.setProperty(key, joinedString);
    }

    public static List<String> getStrings(Properties properties, String key) {
        var joinedString = properties.getProperty(key);
        if (joinedString == null) {
            return List.of();
        }

        int pos = 0;
        var strings = new ArrayList<String>();
        while (pos < joinedString.length()) {
            if (joinedString.charAt(pos) == '"') {
                int end = -1;
                for (int i = pos + 1; i < joinedString.length(); ++i) {
                    if (joinedString.charAt(i) == '"' && joinedString.charAt(i - 1) != '\\') {
                        end = i;
                        break;
                    }
                }
                if (end < 0) {
                    // data corrupted due to missing end quote
                    return List.of();
                }
                strings.add(joinedString.substring(pos + 1, end));
                pos = end + 1;
                if (joinedString.charAt(pos) != ',') {
                    // data corrupted due to missing comma
                    return List.of();
                }
                pos += 1;
            } else {
                int end = joinedString.length();
                for (int i = pos + 1; i < joinedString.length(); ++i) {
                    if (joinedString.charAt(i) == ',') {
                        end = i;
                        break;
                    }
                }
                strings.add(joinedString.substring(pos, end));
                pos = end + 1;
            }
        }
        return strings;
    }

    public static List<File> getFiles(Properties properties, String key) {
        var pathStrings = getStrings(properties, key);
        return pathStrings.stream().map(File::new).toList();
    }

    public static <E extends Enum<E>> List<E> getEnums(Class<E> enumClass,
        Properties properties,
        String key
    ) {
        var enumStrings = getStrings(properties, key);
        return enumStrings.stream().map(s -> {
            try {
                return E.valueOf(enumClass, s);
            } catch (Exception e) {
                return null;
            }
        }).toList();
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
