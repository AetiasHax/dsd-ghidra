import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public abstract class DsdGhidraScript extends GhidraScript {
    protected Properties properties;

    protected File getProjectLocation() {
        GhidraState state = this.getState();
        Project project = state.getProject();
        ProjectData projectData = project.getProjectData();
        ProjectLocator projectLocator = projectData.getProjectLocator();
        return projectLocator.getProjectDir();
    }

    protected File getPropertiesFile() {
        File projectLocation = getProjectLocation();
        String className = this.getClass().getName();
        Path propertiesPath = Paths.get(
            projectLocation.getAbsolutePath(),
            className + ".properties"
        );
        return propertiesPath.toFile();
    }

    protected void loadProperties() {
        File propertiesFile = getPropertiesFile();
        this.properties = new Properties();
        try {
            this.properties.load(new FileInputStream(propertiesFile));
        } catch (IOException ignored) {
        }
    }

    protected void saveProperties() throws IOException {
        File propertiesFile = getPropertiesFile();
        String className = this.getClass().getName();
        this.properties.store(
            new FileOutputStream(propertiesFile),
            "Properties for the " + className + ".java script"
        );
    }
}
