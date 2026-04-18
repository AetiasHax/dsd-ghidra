package dialog;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class DebugMessageDialog extends DialogComponentProvider {
    private static final int PAD = 5;
    private static final Insets INSETS = new Insets(PAD, PAD, PAD, PAD);

    private final String message;

    public DebugMessageDialog(String title, String message) {
        super(title, true, false, true, false);
        this.message = message;

        this.addWorkPanel(buildWorkPanel());
        this.addDismissButton();
        this.addSaveToFileButton();
    }

    public void show() {
        DockingWindowManager.showDialog(null, this);
    }

    private void addSaveToFileButton() {
        okButton = new JButton("Save to File");
        okButton.addActionListener(e -> {
            GhidraFileChooser fileChooser = new GhidraFileChooser(this.getComponent());
            fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
            File file = fileChooser.getSelectedFile();
            if (file.exists()) {
                int choice = OptionDialog.showYesNoDialog(
                    this.getComponent(),
                    "Overwrite file?",
                    "You've selected a file which already exists. Are you sure you want to overwrite it?"
                );
                if (choice != 1) {
                    // Did not choose "Yes"
                    return;
                }
            }
            try (var writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(message);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            dismissCallback();
        });
        addButton(okButton);
    }

    private JComponent buildWorkPanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = INSETS;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;

        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildMessagePanel(), gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildMessagePanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        JTextArea textArea = new JTextArea(message, 20, 80);
        textArea.setFont(Font.decode(Font.MONOSPACED));
        JScrollPane textAreaScrollPane = new JScrollPane(textArea);
        panel.add(textAreaScrollPane, gbc);
        gbc.gridy++;

        return panel;
    }
}
