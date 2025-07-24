package dsdghidra.sync;

import dsdghidra.DsdGhidraPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import org.jetbrains.annotations.NotNull;

public class SyncDelinkFile {
    private final @NotNull Program program;
    private final @NotNull DsdSyncDelinkFile dsdDelinkFile;
    private final @NotNull DsModule dsModule;

    public SyncDelinkFile(
        @NotNull Program program,
        @NotNull DsdSyncDelinkFile dsdDelinkFile,
        @NotNull DsModule dsModule
    ) {
        this.program = program;
        this.dsdDelinkFile = dsdDelinkFile;
        this.dsModule = dsModule;
    }

    private @NotNull String getBookmarkCategory() {
        return dsModule.name;
    }

    private @NotNull String getBookmarkComment(@NotNull String sectionName) {
        return dsdDelinkFile.name.getString() + "(" + sectionName + ")";
    }

    public void addBookmarks() throws DsModule.Exception, DsSection.Exception {
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        BookmarkType delinkFileBookmark = DsdGhidraPlugin.getBookmarkTypeDelinkFile();
        if (delinkFileBookmark == null) {
            return;
        }

        String category = getBookmarkCategory();

        for (DsdSyncBaseSection section : dsdDelinkFile.getSections()) {
            DsSection dsSection = dsModule.getRequiredSection(section);
            Address address = dsSection.getRequiredAddress(section.start_address);
            String sectionName = section.name.getString();
            String comment = getBookmarkComment(sectionName);

            bookmarkManager.setBookmark(address, delinkFileBookmark.getTypeString(), category, comment);
        }
    }
}
