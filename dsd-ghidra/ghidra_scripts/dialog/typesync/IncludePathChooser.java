package dialog.typesync;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.Properties;

public class IncludePathChooser extends GhidraFileChooser {
    private static final String LAST_PATH_KEY = "lastIncludePath";

    private final Properties properties;

    public IncludePathChooser(Component parent, Properties properties) {
        super(parent);
        this.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
        this.setMultiSelectionEnabled(true);

        this.properties = properties;

        if (properties.containsKey(LAST_PATH_KEY)) {
            String lastPath = properties.getProperty(LAST_PATH_KEY);
            this.setSelectedFile(new File(lastPath));
        }
    }

    @Override
    public File getSelectedFile(boolean show) {
        var file = super.getSelectedFile(show);
        this.saveLastPath(file);
        return file;
    }

    @Override
    public List<File> getSelectedFiles() {
        var files = super.getSelectedFiles();
        if (files != null && !files.isEmpty()) {
            this.saveLastPath(files.getFirst());
        }
        return files;
    }

    private void saveLastPath(File file) {
        if (file == null) {
            return;
        }
        if (file.isFile()) {
            file = file.getParentFile();
        }
        this.properties.setProperty(LAST_PATH_KEY, file.toString());
    }
}
