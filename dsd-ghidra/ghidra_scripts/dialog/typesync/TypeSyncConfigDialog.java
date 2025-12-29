package dialog.typesync;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import org.jetbrains.annotations.Nullable;
import dsdghidra.util.PropertiesUtil;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import java.awt.*;
import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class TypeSyncConfigDialog extends DialogComponentProvider {
    private static final String INCLUDES_KEY = "includes";
    private static final String EXCLUDES_KEY = "excludes";

    private static final int PAD = 5;
    private static final Insets INSETS = new Insets(PAD, PAD, PAD, PAD);
    private static final Insets INSETS_EXCEPT_TOP = new Insets(0, PAD, PAD, PAD);
    private static final Insets INSETS_EXCEPT_LEFT = new Insets(PAD, 0, PAD, PAD);
    private static final Insets NO_INSETS = new Insets(0, 0, 0, 0);

    private final Properties properties;

    private final DefaultListModel<File> includesListModel = new DefaultListModel<>();
    private final DefaultListModel<File> excludesListModel = new DefaultListModel<>();

    public TypeSyncConfigDialog(Properties properties) {
        super("Type sync", true, false, true, false);

        this.properties = properties;

        includesListModel.addAll(PropertiesUtil.getFiles(properties, INCLUDES_KEY));
        excludesListModel.addAll(PropertiesUtil.getFiles(properties, EXCLUDES_KEY));

        this.addWorkPanel(buildWorkPanel());
        this.addCancelButton();
        this.addOKButton();
    }

    public record Result(List<File> includes, List<File> excludes) {}

    @Nullable
    private Result result;

    @Nullable
    public Result getResult() {
        DockingWindowManager.showDialog(null, this);
        return result;
    }

    @Override
    protected void okCallback() {
        var includes = Collections.list(includesListModel.elements());
        var excludes = Collections.list(excludesListModel.elements());

        PropertiesUtil.setList(this.properties, INCLUDES_KEY, includes);
        PropertiesUtil.setList(this.properties, EXCLUDES_KEY, excludes);

        this.result = new Result(includes, excludes);
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

        return panel;
    }

    private JComponent buildIncludesExcludesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildPathList("Includes", this.includesListModel), gbc);
        gbc.gridy++;

        gbc.insets = INSETS;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(buildPathList("Excludes", this.excludesListModel), gbc);
        gbc.gridy++;

        return panel;
    }

    private JComponent buildPathList(String title, DefaultListModel<File> listModel) {
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
        JList<File> list = new JList<>(listModel);
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setLayoutOrientation(JList.VERTICAL);
        list.setVisibleRowCount(-1);
        list.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
        JScrollPane listScrollPane = new JScrollPane(list);
        JPanel listPanel = new JPanel(new BorderLayout());
        listPanel.add(listScrollPane, BorderLayout.CENTER);
        panel.add(listPanel, gbc);
        gbc.gridx++;

        gbc.insets = NO_INSETS;
        gbc.weightx = 0.0;
        panel.add(buildPathListButtons(list, listModel), gbc);
        gbc.gridx = 0;
        gbc.gridy++;

        return panel;
    }

    private JComponent buildPathListButtons(JList<File> list, DefaultListModel<File> listModel) {
        JPanel panel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = INSETS_EXCEPT_LEFT;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridx = 0;
        gbc.gridy = 0;

        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton addButton = new JButton("Add");
        addButton.addActionListener(event -> {
            IncludePathChooser pathChooser = new IncludePathChooser(
                this.getComponent(),
                this.properties
            );
            listModel.addAll(pathChooser.getSelectedFiles());
        });
        panel.add(addButton, gbc);
        gbc.gridy++;

        gbc.weighty = 1.0;

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(event -> {
            int[] indices = list.getSelectedIndices();
            for (int i = indices.length - 1; i >= 0; i--) {
                listModel.remove(indices[i]);
            }
        });
        panel.add(removeButton, gbc);
        gbc.gridy++;

        return panel;
    }
}
