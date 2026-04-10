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
import org.jetbrains.annotations.Nullable;

public class SyncRelocation {
    public final @NotNull DsdSyncRelocation dsdRelocation;
    public final @NotNull Address from;
    private final @NotNull Program program;

    public SyncRelocation(@NotNull Program program,
        @NotNull DsSection dsSection,
        @NotNull DsdSyncRelocation dsdRelocation
    ) throws DsSection.Exception {
        Address from = dsSection.getRequiredAddress(dsdRelocation.from);

        this.dsdRelocation = dsdRelocation;
        this.from = from;
        this.program = program;
    }

    public @Nullable String getUpdateReason() {
        ReferenceManager referenceManager = program.getReferenceManager();
        Reference[] references = referenceManager.getReferencesFrom(from);

        switch (dsdRelocation.getKind()) {
            case ArmCall, ThumbCall, ArmCallThumb, ThumbCallArm, ArmBranch, Load -> {
            }
            case OverlayId, LinkTimeConst -> {
                // Only used for linking, not relevant for Ghidra projects
                return null;
            }
        }

        switch (dsdRelocation.getModule()) {
            case None -> {
                if (references.length > 0) {
                    return "There are references at this address but the relocation points to no module";
                }
                return null;
            }
            case Overlays -> {
                if (references.length != dsdRelocation.indices.len) {
                    return String.format(
                        "Currently has %d overlay relocations but should be %d",
                        references.length,
                        dsdRelocation.indices.len
                    );
                }
                short[] overlays = dsdRelocation.indices.getArray();
                for (Reference reference : references) {
                    if (reference.getToAddress().getOffset() != dsdRelocation.to) {
                        return String.format(
                            "An overlay reference points to %08x but should be %08x",
                            reference.getToAddress().getOffset(),
                            dsdRelocation.to
                        );
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
                        return "One or more overlays are missing from the reference list";
                    }
                }
                return null;
            }
            case Main -> {
                if (references.length != 1) {
                    return String.format(
                        "Currently has %d main module relocations but should be 1",
                        references.length
                    );
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return String.format(
                        "This main module reference points to %08x but should be %08x",
                        references[0].getToAddress().getOffset(),
                        dsdRelocation.to
                    );
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                if (!isMain(addressSpaceName)) {
                    return String.format(
                        "This reference points to %s but should point to the main module",
                        addressSpaceName
                    );
                }
                return null;
            }
            case Itcm -> {
                if (references.length != 1) {
                    return String.format(
                        "Currently has %d ITCM relocations but should be 1",
                        references.length
                    );
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return String.format(
                        "This ITCM reference points to %08x but should be %08x",
                        references[0].getToAddress().getOffset(),
                        dsdRelocation.to
                    );
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                if (!isItcm(addressSpaceName)) {
                    return String.format(
                        "This reference points to %s but should point to the ITCM",
                        addressSpaceName
                    );
                }
                return null;
            }
            case Dtcm -> {
                if (references.length != 1) {
                    return String.format(
                        "Currently has %d DTCM relocations but should be 1",
                        references.length
                    );
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return String.format(
                        "This DTCM reference points to %08x but should be %08x",
                        references[0].getToAddress().getOffset(),
                        dsdRelocation.to
                    );
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                if (!isDtcm(addressSpaceName)) {
                    return String.format(
                        "This reference points to %s but should point to the DTCM",
                        addressSpaceName
                    );
                }
                return null;
            }
            case Autoload -> {
                if (references.length != 1) {
                    return String.format(
                        "Currently has %d autoload relocations but should be 1",
                        references.length
                    );
                }
                if (references[0].getToAddress().getOffset() != dsdRelocation.to) {
                    return String.format(
                        "This autoload reference points to %08x but should be %08x",
                        references[0].getToAddress().getOffset(),
                        dsdRelocation.to
                    );
                }
                String addressSpaceName = references[0].getToAddress().getAddressSpace().getName();
                int autoloadIndex = dsdRelocation.indices.getArray()[0];
                if (parseAutoloadIndex(addressSpaceName) != autoloadIndex) {
                    return String.format(
                        "This reference points to %s but should point to autoload %d",
                        addressSpaceName,
                        autoloadIndex
                    );
                }
                return null;
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

    public void addReferences(@NotNull FlatProgramAPI api, @NotNull DsModules dsModules)
        throws DsSection.Exception, DsModules.Exception {
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

    private void addReference(@NotNull FlatProgramAPI api,
        @NotNull DsModule toModule,
        boolean primary
    ) throws DsSection.Exception {
        ReferenceManager referenceManager = program.getReferenceManager();
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        DsSection dsSection = toModule.getRequiredSectionContaining(dsdRelocation.to);
        Address to = dsSection.getAddress(dsdRelocation.to);

        RefType refType = dsdRelocation.getKind().getRefType(dsdRelocation.conditional);

        Reference reference = referenceManager.addMemoryReference(
            from,
            to,
            refType,
            SourceType.USER_DEFINED,
            0
        );
        referenceManager.setPrimary(reference, primary);

        try {
            api.createData(from, undefined4Type);
        } catch (CodeUnitInsertionException ignore) {
        }
    }

    private static boolean isMain(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("ram") || addressSpaceName.equals("arm9_main") || addressSpaceName.equals(
            "arm9_main.bss") || addressSpaceName.equals("ARM9_Main_Memory") || addressSpaceName.equals(
            "ARM9_Main_Memory.bss");
    }

    private static boolean isItcm(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("ram") || addressSpaceName.equals("itcm") || addressSpaceName.equals(
            "ITCM");
    }

    private static boolean isDtcm(@NotNull String addressSpaceName) {
        return addressSpaceName.equals("ram") || addressSpaceName.equals("dtcm") || addressSpaceName.equals(
            "dtcm.bss") || addressSpaceName.equals("DTCM") || addressSpaceName.equals("DTCM.bss");
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
