package dsdghidra.sync;

import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.exception.NotFoundException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;

public class DsModule {
    // Special keys for sectionMap
    public static final String COMBINED_CODE_KEY = "CODE";
    public static final String COMBINED_BSS_KEY = ".bss";

    public final @NotNull String name;
    private final @NotNull Map<String, @NotNull DsSection> sectionMap;

    public DsModule(@NotNull String name) {
        this.name = name;
        this.sectionMap = new HashMap<>();
    }

    public void addSection(@NotNull DsSection section) {
        sectionMap.put(section.getName(), section);
    }

    private @Nullable DsSection getSection(@NotNull String name) {
        return sectionMap.get(name);
    }

    public @Nullable DsSection getSection(@NotNull DsdSyncBaseSection section) {
        if (isSplit()) {
            return getSection(section.name.getString());
        }
        switch (section.getKind()) {
            case Code, Data -> {
                return getSection(COMBINED_CODE_KEY);
            }
            case Bss -> {
                return getSection(COMBINED_BSS_KEY);
            }
        }
        return null;
    }

    public @NotNull DsSection getRequiredSection(@NotNull DsdSyncBaseSection section) throws DsModule.Exception {
        DsSection dsSection = getSection(section);
        if (dsSection == null) {
            throw new DsModule.Exception(String.format(
                "Failed to find section %s in module %s",
                section.name,
                name
            ));
        }
        return dsSection;
    }

    public @NotNull Collection<DsSection> getSections() {
        return sectionMap.values();
    }

    public boolean isSplit() {
        return !sectionMap.containsKey(COMBINED_CODE_KEY);
    }

    public void split(
        @NotNull Program program,
        @NotNull DsdSyncModule dsdModule
    ) throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException, Exception {
        if (isSplit()) {
            return;
        }

        DsSection combinedCodeSection = sectionMap.remove(COMBINED_CODE_KEY);
        DsSection combinedBssSection = sectionMap.remove(COMBINED_BSS_KEY);

        List<DsdSyncSection> dsdCodeSections = new ArrayList<>();
        List<DsdSyncSection> dsdBssSections = new ArrayList<>();

        for (DsdSyncSection section : dsdModule.getSections()) {
            if (section.base.getKind().isBss()) {
                dsdBssSections.add(section);
            } else {
                dsdCodeSections.add(section);
            }
        }

        dsdCodeSections.sort(Comparator.comparingInt(a -> a.base.start_address));
        dsdBssSections.sort(Comparator.comparingInt(a -> a.base.start_address));

        splitSection(program, combinedCodeSection, dsdCodeSections);
        splitSection(program, combinedBssSection, dsdBssSections);
    }

    private void splitSection(
        @NotNull Program program,
        @Nullable DsSection section,
        @NotNull List<DsdSyncSection> dsdSections
    ) throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException, Exception {
        if (section == null) {
            return;
        }

        Memory memory = program.getMemory();

        DsSection sectionToSplit = section;
        for (int i = 0; i < dsdSections.size() - 1; i++) {
            DsdSyncSection dsdSection = dsdSections.get(i);
            DsdSyncSection nextDsdSection = dsdSections.get(i + 1);

            DsSection.Split splits;
            try {
                splits = sectionToSplit.split(memory, nextDsdSection.base.start_address);
            } catch (DsSection.Exception e) {
                throw new DsModule.Exception(String.format(
                    "Failed to split section %s at address %08x (after %s) in module %s",
                    nextDsdSection.base.name.getString(),
                    nextDsdSection.base.start_address,
                    dsdSection.base.name.getString(),
                    name
                ), e);
            }
            if (splits.first() != null) {
                splits.first().setName(dsdSection.base.name.getString());
                splits.first().setRwxFlags(dsdSection.base.getKind());
                addSection(splits.first());
            }

            sectionToSplit = splits.second();
        }

        DsdSyncSection lastDsdSection = dsdSections.getLast();
        sectionToSplit.setName(lastDsdSection.base.name.getString());
        sectionToSplit.setRwxFlags(lastDsdSection.base.getKind());
        addSection(sectionToSplit);
    }

    public void join(
        @NotNull Program program
    ) throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
        if (!isSplit()) {
            return;
        }

        List<DsSection> codeSections = new ArrayList<>();
        List<DsSection> bssSections = new ArrayList<>();

        for (DsSection dsSection : sectionMap.values()) {
            if (dsSection.getMemoryBlock().isInitialized()) {
                codeSections.add(dsSection);
            } else {
                bssSections.add(dsSection);
            }
        }

        sectionMap.clear();

        codeSections.sort(Comparator.comparingInt(DsSection::getMinAddress));
        bssSections.sort(Comparator.comparingInt(DsSection::getMinAddress));

        joinSection(program, codeSections, COMBINED_CODE_KEY);
        joinSection(program, bssSections, COMBINED_BSS_KEY);
    }

    private void joinSection(
        @NotNull Program program,
        @NotNull List<DsSection> dsSections,
        @NotNull String combinedName
    ) throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
        Memory memory = program.getMemory();

        if (dsSections.isEmpty()) {
            return;
        }

        DsSection sectionToJoin = dsSections.getFirst();

        for (int i = 1; i < dsSections.size(); i++) {
            DsSection dsSection = dsSections.get(i);
            sectionToJoin.join(memory, dsSection);
        }

        sectionToJoin.setName(combinedName);
        sectionToJoin.resetRwxFlags();
        addSection(sectionToJoin);
    }

    public @NotNull String toString(int indent) {
        String pad = new String(new char[indent]).replace('\0', ' ');
        String pad2 = new String(new char[indent + 2]).replace('\0', ' ');
        String pad4 = new String(new char[indent + 4]).replace('\0', ' ');

        List<String> sections = this.sectionMap
            .entrySet()
            .stream()
            .map(entry -> pad4 + entry.getKey() + ": " + entry.getValue())
            .toList();

        return pad + "DsModule{\n" + pad2 + "name=" + name + ",\n" + pad2 + "sectionMap={\n" +
            String.join(",\n", sections) + "\n" + pad2 + "}\n" + pad + "}";
    }

    public @Nullable DsSection getSectionContaining(int address) {
        for (DsSection section : sectionMap.values()) {
            if (section.contains(address)) {
                return section;
            }
        }
        return null;
    }

    public @NotNull DsSection getRequiredSectionContaining(int address) throws DsSection.Exception {
        DsSection section = this.getSectionContaining(address);
        if (section == null) {
            throw new DsSection.Exception(String.format(
                "No section found at address %08x in module '%s'",
                address,
                this.name
            ));
        }
        return section;
    }

    public static final class Exception extends java.lang.Exception {
        public Exception(String message) {
            super(message);
        }

        public Exception(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
