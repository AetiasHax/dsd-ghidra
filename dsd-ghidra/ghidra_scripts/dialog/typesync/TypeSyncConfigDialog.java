package dialog.typesync;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import dsdghidra.util.PropertiesUtil;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.Properties;

public class TypeSyncConfigDialog extends DialogComponentProvider {
    private static final String PROJECT_PATH_KEY = "projectPath";
    private static final String INCLUDES_KEY = "includes";
    private static final String FILES_KEY = "files";
    private static final String LANGUAGES_KEY = "languages";
    private static final String SHORT_ENUMS_KEY = "shortEnums";
    private static final String SIGNED_CHAR_KEY = "signedChar";
    private static final String DRY_RUN_KEY = "dryRun";
    private static final String DELETE_OLD_TYPES_KEY = "deleteOldTypes";
    private static final String DUMP_YAML_KEY = "dumpYaml";

    private static final int PAD = 5;
    private static final Insets INSETS = new Insets(PAD, PAD, PAD, PAD);
    private static final Insets INSETS_EXCEPT_TOP = new Insets(0, PAD, PAD, PAD);
    private static final Insets INSETS_EXCEPT_LEFT = new Insets(PAD, 0, PAD, PAD);
    private static final Insets NO_INSETS = new Insets(0, 0, 0, 0);

    private final Properties properties;

    private final JTextField projectPathField;

    private final JTable includesTable;
    private final JTable filesTable;
    private final DefaultTableModel includesTableModel;
    private final DefaultTableModel filesTableModel;

    private final JCheckBox shortEnumsCheckbox;
    private final JCheckBox signedCharCheckbox;
    private final JCheckBox dryRunCheckbox;
    private final JCheckBox deleteOldTypesCheckbox;
    private final JCheckBox dumpYamlCheckbox;

    public TypeSyncConfigDialog(Properties properties) {
        super("Type sync", true, false, true, false);

        this.properties = properties;

        this.projectPathField = new JTextField(properties.getProperty(PROJECT_PATH_KEY, ""));

        List<String> includesStrings = PropertiesUtil.getStrings(properties, INCLUDES_KEY);
        Object[][] includesRows = new Object[includesStrings.size()][];
        for (int i = 0; i < includesStrings.size(); ++i) {
            includesRows[i] = new Object[] {includesStrings.get(i)};
        }
        includesTableModel = new DefaultTableModel(includesRows, new Object[] {"Glob"});
        includesTable = new JTable(includesTableModel);

        List<String> filesStrings = PropertiesUtil.getStrings(properties, FILES_KEY);
        List<Language> languages = PropertiesUtil.getEnums(
            Language.class,
            properties,
            LANGUAGES_KEY
        );
        Object[][] filesRows = new Object[filesStrings.size()][];
        for (int i = 0; i < filesStrings.size(); ++i) {
            Language language = i < languages.size() ? languages.get(i) : Language.Detect;
            filesRows[i] = new Object[] {filesStrings.get(i), language};
        }
        filesTableModel = new DefaultTableModel(filesRows, new Object[] {"Glob", "Language"});
        filesTable = new JTable(filesTableModel);
        filesTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        JComboBox<Language> comboBox = new JComboBox<>(Language.values());
        comboBox.setRenderer(new LanguageListCellRenderer());
        TableColumn languageColumn = filesTable.getColumnModel().getColumn(1);
        languageColumn.setCellEditor(new DefaultCellEditor(comboBox));
        languageColumn.setCellRenderer(new LanguageTableCellRenderer());
        languageColumn.setPreferredWidth(40);

        this.shortEnumsCheckbox = new JCheckBox(
            "Short enums",
            PropertiesUtil.getBoolean(this.properties, SHORT_ENUMS_KEY, false)
        );
        this.signedCharCheckbox = new JCheckBox(
            "Signed char",
            PropertiesUtil.getBoolean(this.properties, SIGNED_CHAR_KEY, true)
        );
        this.dryRunCheckbox = new JCheckBox(
            "Dry run",
            PropertiesUtil.getBoolean(this.properties, DRY_RUN_KEY, false)
        );
        this.deleteOldTypesCheckbox = new JCheckBox(
            "Delete old types",
            PropertiesUtil.getBoolean(this.properties, DELETE_OLD_TYPES_KEY, true)
        );
        this.dumpYamlCheckbox = new JCheckBox(
            "Dump YAML",
            PropertiesUtil.getBoolean(this.properties, DUMP_YAML_KEY, false)
        );

        this.addWorkPanel(buildWorkPanel());
        this.addOKButton();
        this.addCancelButton();
    }

    public record Result(
        String projectPath,
        List<String> includes,
        List<String> files,
        List<Language> languages,
        boolean shortEnums,
        boolean signedChar,
        boolean dryRun,
        boolean deleteOldTypes,
        boolean dumpYaml
    ) {}

    @Nullable
    private Result result;

    @Nullable
    public Result getResult() {
        DockingWindowManager.showDialog(null, this);
        return result;
    }

    @Override
    protected void okCallback() {
        String projectPath = this.projectPathField.getText();

        var includes = this.includesTableModel
            .getDataVector()
            .stream()
            .map(vector -> (String) vector.getFirst())
            .toList();
        var files = this.filesTableModel
            .getDataVector()
            .stream()
            .map(vector -> (String) vector.getFirst())
            .toList();
        var languages = this.filesTableModel
            .getDataVector()
            .stream()
            .map(vector -> (Language) vector.get(1))
            .toList();
        boolean shortEnums = this.shortEnumsCheckbox.isSelected();
        boolean signedChar = this.signedCharCheckbox.isSelected();
        boolean dryRun = this.dryRunCheckbox.isSelected();
        boolean deleteOldTypes = this.deleteOldTypesCheckbox.isSelected();
        boolean dumpYaml = this.dumpYamlCheckbox.isSelected();

        this.properties.setProperty(PROJECT_PATH_KEY, projectPath);
        PropertiesUtil.setList(this.properties, INCLUDES_KEY, includes);
        PropertiesUtil.setList(this.properties, FILES_KEY, files);
        PropertiesUtil.setList(this.properties, LANGUAGES_KEY, languages);
        PropertiesUtil.setBoolean(this.properties, SHORT_ENUMS_KEY, shortEnums);
        PropertiesUtil.setBoolean(this.properties, SIGNED_CHAR_KEY, signedChar);
        PropertiesUtil.setBoolean(this.properties, DRY_RUN_KEY, dryRun);
        PropertiesUtil.setBoolean(this.properties, DELETE_OLD_TYPES_KEY, deleteOldTypes);
        PropertiesUtil.setBoolean(this.properties, DUMP_YAML_KEY, dumpYaml);

        this.result = new Result(
            projectPath,
            includes,
            files,
            languages,
            shortEnums,
            signedChar,
            dryRun,
            deleteOldTypes,
            dumpYaml
        );
        this.close();
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
        panel.add(buildIncludesExcludesPanel(), gbc);
        gbc.gridy++;

        gbc.weighty = 0.0;

        panel.add(buildOptionsPanel(), gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildOptionsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        gbc.weighty = 1.0;
        gbc.weightx = 1.0;

        gbc.insets = NO_INSETS;
        panel.add(this.buildClangOptionsPanel(), gbc);
        gbc.gridx++;

        gbc.weightx = 0.0;

        gbc.insets = NO_INSETS;
        panel.add(this.buildTypesyncOptionsPanel(), gbc);
        gbc.gridx++;

        return panel;
    }

    private JComponent buildClangOptionsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "Clang options"
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        gbc.weightx = 1.0;

        gbc.insets = NO_INSETS;
        panel.add(this.shortEnumsCheckbox, gbc);
        gbc.gridy++;

        gbc.insets = NO_INSETS;
        panel.add(this.signedCharCheckbox, gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildTypesyncOptionsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "Typesync options"
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        gbc.weightx = 1.0;

        gbc.insets = NO_INSETS;
        panel.add(this.dryRunCheckbox, gbc);
        gbc.gridy++;

        gbc.insets = NO_INSETS;
        panel.add(this.deleteOldTypesCheckbox, gbc);
        gbc.gridy++;

        gbc.weighty = 1.0;

        gbc.insets = NO_INSETS;
        panel.add(this.dumpYamlCheckbox, gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildIncludesExcludesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildProjectPathChooser(), gbc);
        gbc.gridy++;

        gbc.weighty = 1.0;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildPathList("Include directories", this.includesTable), gbc);
        gbc.gridy++;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildPathList("C/C++ files to sync types from", this.filesTable), gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildProjectPathChooser() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;

        gbc.weightx = 1.0;

        gbc.insets = INSETS;
        panel.add(new JLabel("Project path:"));
        gbc.gridx++;

        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(this.projectPathField, gbc);
        gbc.gridx++;

        gbc.weightx = 0.0;

        gbc.insets = INSETS_EXCEPT_LEFT;
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            ProjectPathChooser pathChooser = new ProjectPathChooser(
                this.getComponent(),
                this.properties
            );
            File path = pathChooser.getSelectedFile(true);
            this.projectPathField.setText(path.getAbsolutePath());
        });
        panel.add(browseButton, gbc);
        gbc.gridx++;

        return panel;
    }

    private JComponent buildPathList(String title, JTable table) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;

        gbc.insets = INSETS;
        JLabel titleLabel = new JLabel(title);
        panel.add(titleLabel, gbc);
        gbc.gridy++;

        gbc.insets = INSETS_EXCEPT_TOP;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        table.setTableHeader(null);
        JScrollPane tableScrollPane = new JScrollPane(table);
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.add(tableScrollPane, BorderLayout.CENTER);
        panel.add(tablePanel, gbc);
        gbc.gridx++;

        gbc.insets = NO_INSETS;
        gbc.weightx = 0.0;
        panel.add(buildPathListButtons(table), gbc);
        gbc.gridx = 0;
        gbc.gridy++;

        return panel;
    }

    private JComponent buildPathListButtons(JTable table) {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = INSETS_EXCEPT_LEFT;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridx = 0;
        gbc.gridy = 0;

        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton addButton = new JButton("Add");
        DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
        addButton.addActionListener(event -> {
            tableModel.addRow(new Object[] {
                "Enter glob pattern (absolute or relative)", Language.Detect
            });
            table.editCellAt(tableModel.getRowCount() - 1, 0);
            JTextComponent editor = (JTextComponent) table.getEditorComponent();
            editor.requestFocusInWindow();
            editor.selectAll();
        });
        panel.add(addButton, gbc);
        gbc.gridy++;

        gbc.weighty = 1.0;

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(event -> {
            int[] rows = table.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) {
                tableModel.removeRow(rows[i]);
            }
        });
        panel.add(removeButton, gbc);
        gbc.gridy++;

        return panel;
    }

    public enum Language {
        Detect("Detect language"), C("C"), Cpp("C++");

        public final String description;

        Language(String description) {
            this.description = description;
        }
    }

    private static class LanguageListCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list,
            Object value,
            int index,
            boolean isSelected,
            boolean cellHasFocus
        ) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value instanceof Language) {
                setText(((Language) value).description);
            }
            return this;
        }
    }

    private static class LanguageTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        protected void setValue(Object value) {
            if (value instanceof Language) {
                setText(((Language) value).description);
            } else {
                setText("");
            }
        }
    }
}
