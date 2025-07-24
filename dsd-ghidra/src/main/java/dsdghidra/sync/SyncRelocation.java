package dsdghidra.sync;

import dsdghidra.util.DataTypeUtil;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import org.jetbrains.annotations.NotNull;

public class SyncRelocation {
    public final @NotNull DsdSyncRelocation dsdRelocation;
    public final @NotNull Address from;
    private final @NotNull Program program;

    public SyncRelocation(
        @NotNull Program program,
        @NotNull DsSection dsSection,
        @NotNull DsdSyncRelocation dsdRelocation
    ) throws DsSection.Exception {
        Address from = dsSection.getRequiredAddress(dsdRelocation.from);

        this.dsdRelocation = dsdRelocation;
        this.from = from;
        this.program = program;
    }

    public boolean needsUpdate() {
        ReferenceManager referenceManager = program.getReferenceManager();
        Reference[] references = referenceManager.getReferencesFrom(from);

        switch (dsdRelocation.getModule()) {
            case None -> {
                return references.length > 0;
            }
            case Overlays -> {
                if (dsdRelocation.indices.len != references.length) {
                    return true;
                }
                short[] overlays = dsdRelocation.indices.getArray();
                for (Reference reference : references) {
                    if (reference.getToAddress().getOffset() != dsdRelocation.to) {
                        return true;
                    }

                    String addressSpaceName = reference.getToAddress().getAddressSpace().getName();
                    int toOverlay = parseOverlayNumber(addressSpaceName);
                    boolean found = false;
                    for (short overlay : overlays) {
                        if (toOverlay == overlay) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return true;
                    }
                }
                return false;
            }
            case Main -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return isMain(addressSpaceName);
            }
            case Itcm -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return isItcm(addressSpaceName);
            }
            case Dtcm -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                return isDtcm(addressSpaceName);
            }
            case Autoload -> {
                if (references.length != 1) {
                    return true;
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return true;
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                int autoloadIndex = dsdRelocation.indices.getArray()[0];
                return parseAutoloadIndex(addressSpaceName) == autoloadIndex;
            }
        }
        throw new MatchException("Unknown relocation type", null);
    }

    public boolean existsInGhidra() {
        ReferenceManager referenceManager = program.getReferenceManager();
        return referenceManager.getReferencesFrom(from).length > 0;
    }

    public void deleteExistingReferences() {
        ReferenceManager referenceManager = program.getReferenceManager();
        referenceManager.removeAllReferencesFrom(from);
    }

    public void addReferences(@NotNull FlatProgramAPI api, @NotNull DsModules dsModules) throws DsSection.Exception, DsModules.Exception {
        switch (dsdRelocation.getModule()) {
            case None -> {
            }
            case Overlays -> {
                short[] array = dsdRelocation.indices.getArray();
                for (int i = 0; i < array.length; i++) {
                    short id = array[i];
                    boolean primary = i == 0;
                    this.addReference(api, dsModules.getRequiredOverlay(id), primary);
                }
            }
            case Main -> this.addReference(api, dsModules.main, true);
            case Itcm -> this.addReference(api, dsModules.itcm, true);
            case Dtcm -> this.addReference(api, dsModules.dtcm, true);
            case Autoload -> {
                int autoloadIndex = dsdRelocation.indices.getArray()[0];
                this.addReference(api, dsModules.getRequiredAutoload(autoloadIndex), true);
            }
        }
    }

    private void addReference(
        @NotNull FlatProgramAPI api,
        @NotNull DsModule toModule,
        boolean primary
    ) throws DsSection.Exception {
        ReferenceManager referenceManager = program.getReferenceManager();
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        DsSection dsSection = toModule.getRequiredSectionContaining(dsdRelocation.to);
        Address to = dsSection.getAddress(dsdRelocation.to);

        RefType refType = dsdRelocation.getKind().getRefType(dsdRelocation.conditional);

        Reference reference = referenceManager.addMemoryReference(from, to, refType, SourceType.USER_DEFINED, 0);
        referenceManager.setPrimary(reference, primary);

        try {
            api.createData(from, undefined4Type);
        } catch (CodeUnitInsertionException ignore) {
        }
    }

    private static boolean isMain(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("arm9_main") ||
            addressSpaceName.equals("arm9_main.bss") ||
            addressSpaceName.equals("ARM9_Main_Memory") ||
            addressSpaceName.equals("ARM9_Main_Memory.bss");
    }

    private static boolean isItcm(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("itcm") ||
            addressSpaceName.equals("ITCM");
    }

    private static boolean isDtcm(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("dtcm") ||
            addressSpaceName.equals("dtcm.bss") ||
            addressSpaceName.equals("DTCM") ||
            addressSpaceName.equals("DTCM.bss");
    }

    private static int parseAutoloadIndex(@NotNull String blockName) {
        int sectionStartIndex = blockName.indexOf('.');
        if (sectionStartIndex >= 0) {
            blockName = blockName.substring(0, sectionStartIndex);
        }
        return DsModules.getAutoloadIndex(blockName);
    }

    private static int parseOverlayNumber(@NotNull String blockName) {
        int sectionStartIndex = blockName.indexOf('.');
        if (sectionStartIndex >= 0) {
            blockName = blockName.substring(0, sectionStartIndex);
        }
        return DsModules.getOverlayId(blockName);
    }
}
