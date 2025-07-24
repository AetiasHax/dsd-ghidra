package dsdghidra.sync;

import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.exception.NotFoundException;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.List;

public class SyncModule {
    private final @NotNull Program program;
    private final @NotNull DsdSyncModule dsdModule;
    private final @NotNull DsModule dsModule;

    public SyncModule(@NotNull Program program, @NotNull DsdSyncModule dsdModule, @NotNull DsModule dsModule) {
        this.program = program;
        this.dsdModule = dsdModule;
        this.dsModule = dsModule;
    }

    public boolean needsUpdate() {
        if (!dsModule.isSplit()) {
            return true;
        }

        List<DsdSyncSection> dsdSyncSections = Arrays
            .stream(dsdModule.getSections())
            .filter(module -> !module.base.isEmpty())
            .toList();
        if (dsModule.getSections().size() != dsdSyncSections.size()) {
            return true;
        }

        for (DsdSyncSection dsdSyncSection : dsdSyncSections) {
            DsSection dsSection = dsModule.getSection(dsdSyncSection.base);
            if (dsSection == null) {
                System.out.println(dsdSyncSection.base.name.getString() + " does not exist");
                return true;
            }
            if (!dsSection.matches(dsdSyncSection)) {
                return true;
            }
        }

        return false;
    }

    public void split()
        throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException, DsModule.Exception {
        dsModule.split(program, dsdModule);
    }

    public void join()
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
        dsModule.join(program);
    }
}
