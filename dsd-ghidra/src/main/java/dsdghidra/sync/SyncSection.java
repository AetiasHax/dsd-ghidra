package dsdghidra.sync;


import dsdghidra.DsdGhidraPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class SyncSection {
    private final Program program;
    private final DsSection dsSection;
    private final DsModule dsModule;

    public SyncSection(Program program, DsSection dsSection, DsModule dsModule) {
        this.program = program;
        this.dsSection = dsSection;
        this.dsModule = dsModule;
    }

    public Address getBookmarkAddress() {
        return dsSection.getAddress(dsSection.getMinAddress());
    }

    private String getBookmarkCategory() {
        return dsModule.name;
    }

    private String getBookmarkComment() {
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
