package dsdghidra.sync;


import dsdghidra.DsdGhidraPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class SyncSection {
    private final @NotNull Program program;
    private final @NotNull DsSection dsSection;
    private final @NotNull DsModule dsModule;

    public SyncSection(@NotNull Program program, @NotNull DsSection dsSection, @NotNull DsModule dsModule) {
        this.program = program;
        this.dsSection = dsSection;
        this.dsModule = dsModule;
    }

    public @Nullable Address getBookmarkAddress() {
        return dsSection.getAddress(dsSection.getMinAddress());
    }

    private @NotNull String getBookmarkCategory() {
        return dsModule.name;
    }

    private @NotNull String getBookmarkComment() {
        return dsSection.getName();
    }

    public void addBookmark() {
        BookmarkManager bookmarkManager = program.getBookmarkManager();
        BookmarkType sectionBookmark = DsdGhidraPlugin.getBookmarkTypeSection();
        if (sectionBookmark == null) {
            return;
        }

        Address address = getBookmarkAddress();
        String category = getBookmarkCategory();
        String comment = getBookmarkComment();
        bookmarkManager.setBookmark(address, sectionBookmark.getTypeString(), category, comment);
    }
}
