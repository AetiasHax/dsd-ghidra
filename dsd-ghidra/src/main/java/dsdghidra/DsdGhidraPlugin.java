package dsdghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.Objects;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = DsdPluginPackage.NAME,
    category = PluginCategoryNames.PROGRAM_ORGANIZATION,
    shortDescription = "Plugin for dsd-ghidra",
    description = "Plugin for dsd-ghidra"
)
public class DsdGhidraPlugin extends ProgramPlugin {
    public static final String SECTION_BOOKMARK = "DSD_SECTION";
    public static final String DELINK_FILE_BOOKMARK = "DSD_DELINK_FILE";

    private final Icon sectionIcon;
    private final Icon delinkFileIcon;

    private static BookmarkType BOOKMARK_TYPE_SECTION;
    private static BookmarkType BOOKMARK_TYPE_DELINK_FILE;

    public DsdGhidraPlugin(PluginTool plugintool) {
        super(plugintool);

        URL sectionIconUrl = DsdGhidraPlugin.class.getClassLoader().getResource("images/bookmark_section.png");
        URL delinkFileIconUrl = DsdGhidraPlugin.class.getClassLoader().getResource("images/bookmark_delink_file.png");

        Objects.requireNonNull(sectionIconUrl);
        Objects.requireNonNull(delinkFileIconUrl);

        this.sectionIcon = new ImageIcon(sectionIconUrl);
        this.delinkFileIcon = new ImageIcon(delinkFileIconUrl);
    }

    @Override
    protected void programOpened(Program program) {
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        BOOKMARK_TYPE_SECTION = bookmarkManager.defineType(SECTION_BOOKMARK, sectionIcon, new Color(0x6abe30), 0);
        BOOKMARK_TYPE_DELINK_FILE = bookmarkManager.defineType(DELINK_FILE_BOOKMARK,
            delinkFileIcon,
            new Color(0x0095e9),
            0
        );
    }

    public static BookmarkType getBookmarkTypeSection() {
        return BOOKMARK_TYPE_SECTION;
    }

    public static BookmarkType getBookmarkTypeDelinkFile() {
        return BOOKMARK_TYPE_DELINK_FILE;
    }
}
