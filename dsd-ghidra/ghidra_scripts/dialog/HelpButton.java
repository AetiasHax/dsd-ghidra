package dialog;

import javax.swing.*;
import java.awt.*;

public class HelpButton extends JButton {
    public HelpButton(Component parent, String helpMessage) {
        super("?");
        addActionListener(e -> {
            JOptionPane.showMessageDialog(parent, helpMessage);
        });
        setPreferredSize(new Dimension(20, 20));
        setBackground(getBackground().darker());
    }
}
