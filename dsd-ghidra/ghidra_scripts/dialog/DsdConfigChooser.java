package dialog;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.script.GhidraScriptProperties;

import java.awt.*;
import java.io.File;
import java.util.Properties;

public class DsdConfigChooser extends GhidraFileChooser {
    public static final String LAST_CONFIG_KEY = "DsdConfigChooserLastConfig";

    protected boolean dryRun = false;

    public DsdConfigChooser(Component parent, String approveText, Properties properties) {
        super(parent);
        this.setApproveButtonText(approveText);
        this.addApplyButton();
        applyButton.setText(approveText + " (dry run)");

        this.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        this.setTitle("Path to config.yaml from dsd");

        if (properties.containsKey(LAST_CONFIG_KEY)) {
            String lastConfig = properties.getProperty(LAST_CONFIG_KEY);
            this.setSelectedFile(new File(lastConfig));
        }
    }

    @Override
    protected void applyCallback() {
        dryRun = true;
        this.okCallback();
    }

    public boolean isDryRun() {
        return dryRun;
    }
}
