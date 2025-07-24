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

public class SyncRelocation {
    public final DsdSyncRelocation dsdRelocation;
    public final Address from;
    private final Program program;

    public SyncRelocation(Program program, DsSection dsSection, DsdSyncRelocation dsdRelocation) {
        Address from = dsSection.getAddress(dsdRelocation.from);

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

    public void addReferences(FlatProgramAPI api, DsModules dsModules) {
        switch (dsdRelocation.getModule()) {
            case None -> {
            }
            case Overlays -> {
                short[] array = dsdRelocation.indices.getArray();
                for (int i = 0; i < array.length; i++) {
                    short id = array[i];
                    boolean primary = i == 0;
                    this.addReference(api, dsModules.getOverlay(id), primary);
                }
            }
            case Main -> this.addReference(api, dsModules.main, true);
            case Itcm -> this.addReference(api, dsModules.itcm, true);
            case Dtcm -> this.addReference(api, dsModules.dtcm, true);
            case Autoload -> {
                int autoloadIndex = dsdRelocation.indices.getArray()[0];
                this.addReference(api, dsModules.getAutoload(autoloadIndex), true);
            }
        }
    }

    private void addReference(FlatProgramAPI api, DsModule toModule, boolean primary) {
        ReferenceManager referenceManager = program.getReferenceManager();
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        DsSection dsSection = toModule.getSectionContaining(dsdRelocation.to);
        Address to = dsSection.getAddress(dsdRelocation.to);

        RefType refType = dsdRelocation.getKind().getRefType(dsdRelocation.conditional);

        Reference reference = referenceManager.addMemoryReference(from, to, refType, SourceType.USER_DEFINED, 0);
        referenceManager.setPrimary(reference, primary);

        try {
            api.createData(from, undefined4Type);
        } catch (CodeUnitInsertionException ignore) {
        }
    }

    private static boolean isMain(String addressSpaceName) {
        return addressSpaceName.equals("arm9_main") ||
            addressSpaceName.equals("arm9_main.bss") ||
            addressSpaceName.equals("ARM9_Main_Memory") ||
            addressSpaceName.equals("ARM9_Main_Memory.bss");
    }

    private static boolean isItcm(String addressSpaceName) {
        return addressSpaceName.equals("itcm") ||
            addressSpaceName.equals("ITCM");
    }

    private static boolean isDtcm(String addressSpaceName) {
        return addressSpaceName.equals("dtcm") ||
            addressSpaceName.equals("dtcm.bss") ||
            addressSpaceName.equals("DTCM") ||
            addressSpaceName.equals("DTCM.bss");
    }

    private static int parseAutoloadIndex(String blockName) {
        int sectionStartIndex = blockName.indexOf('.');
        if (sectionStartIndex >= 0) {
            blockName = blockName.substring(0, sectionStartIndex);
        }
        return DsModules.getAutoloadIndex(blockName);
    }

    private static int parseOverlayNumber(String blockName) {
        int sectionStartIndex = blockName.indexOf('.');
        if (sectionStartIndex >= 0) {
            blockName = blockName.substring(0, sectionStartIndex);
        }
        return DsModules.getOverlayId(blockName);
    }
}
