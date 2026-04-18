package dialog.typesync;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

import java.awt.*;
import java.io.File;
import java.util.Properties;

public class ProjectPathChooser extends GhidraFileChooser {
    private static final String LAST_PATH_KEY = "lastProjectPath";

    private final Properties properties;

    public ProjectPathChooser(Component parent, Properties properties) {
        super(parent);
        this.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
        this.setMultiSelectionEnabled(false);

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
