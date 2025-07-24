package dsdghidra.sync;


import dsdghidra.DsdGhidraPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import org.jetbrains.annotations.NotNull;

public class SyncSection {
    private static final int SECTION_COMMENT_TYPE = CodeUnit.PLATE_COMMENT;
    private static final String SECTION_COMMENT_START = "Start of section";

    private final Program program;
    private final DsdSyncSection dsdSection;
    private final DsSection dsSection;
    private final DsModule dsModule;

    public SyncSection(Program program, DsdSyncSection dsdSection, DsSection dsSection, DsModule dsModule) {
        this.program = program;
        this.dsdSection = dsdSection;
        this.dsSection = dsSection;
        this.dsModule = dsModule;
    }

    /**
     * @deprecated Replaced in favor of bookmarks
     */
    @Deprecated
    public void removeComments() {
        Listing listing = program.getListing();

        AddressSet addressSet = new AddressSet(dsSection.getMemoryBlock().getAddressRange());
        for (Address address : listing.getCommentAddressIterator(SECTION_COMMENT_TYPE, addressSet, true)) {
            String comment = listing.getComment(SECTION_COMMENT_TYPE, address);
            if (!comment.startsWith(SECTION_COMMENT_START)) {
                continue;
            }

            listing.clearComments(address, address.next());
        }
    }

    /**
     * @deprecated Replaced in favor of bookmarks
     */
    @Deprecated
    public void addSectionComment(boolean dryRun)
    throws Exception {
        this.addComment(dryRun, "");
    }

    /**
     * @deprecated Replaced in favor of bookmarks
     */
    @Deprecated
    public void addComment(boolean dryRun, String fileName)
    throws Exception {
        Listing listing = program.getListing();

        DsSection dsSection = dsModule.getSection(dsdSection.base);
        if (dsSection == null) {
            return;
        }
        Address start = dsSection.getAddress(dsdSection.base.start_address);
        if (start == null) {
            String error = getAddressRangeNotMatchingError(fileName, dsSection);
            throw new Exception(error);
        }

        String comment = SECTION_COMMENT_START + " " + dsdSection.base.name.getString();
        if (!fileName.isEmpty()) {
            comment += "(" + fileName + ")";
        }

        if (!dryRun) {
            listing.setComment(start, SECTION_COMMENT_TYPE, comment);
        }
    }

    private @NotNull String getAddressRangeNotMatchingError(String fileName, DsSection dsSection) {
        String error = "Section's address range does not match parent module '" + dsModule.name + "'\n";
        error += "Section: " + fileName + dsdSection.base.name.getString();
        error += "[" + Integer.toHexString(dsdSection.base.start_address);
        error += ".." + Integer.toHexString(dsdSection.base.end_address) + "]\n";
        error += "Parent: " + dsModule.name + dsSection.getName();
        error += "[" + Integer.toHexString(dsSection.getMinAddress());
        error += ".." + Integer.toHexString(dsSection.getMaxAddress()) + "]\n";
        return error;
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
