package dsdghidra.sync;

import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.exception.NotFoundException;
import org.jetbrains.annotations.Nullable;

import java.util.*;

public class DsModule {
    // Special keys for sectionMap
    public static final String COMBINED_CODE_KEY = "CODE";
    public static final String COMBINED_BSS_KEY = ".bss";

    public final String name;
    private final Map<String, DsSection> sectionMap;

    public DsModule(String name) {
        this.name = name;
        this.sectionMap = new HashMap<>();
    }

    public void addSection(DsSection section) {
        sectionMap.put(section.getName(), section);
    }

    private DsSection getSection(String name) {
        return sectionMap.get(name);
    }

    public DsSection getSection(DsdSyncBaseSection section) {
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

    public Collection<DsSection> getSections() {
        return sectionMap.values();
    }

    public boolean isSplit() {
        return !sectionMap.containsKey(COMBINED_CODE_KEY);
    }

    public void split(Program program, DsdSyncModule dsdModule)
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
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

    private void splitSection(Program program, DsSection section, List<DsdSyncSection> dsdSections)
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
        if (section == null) {
            return;
        }

        Memory memory = program.getMemory();

        DsSection sectionToSplit = section;
        for (int i = 0; i < dsdSections.size() - 1; i++) {
            DsdSyncSection dsdSection = dsdSections.get(i);
            DsdSyncSection nextDsdSection = dsdSections.get(i + 1);

            DsSection.Split splits = sectionToSplit.split(memory, nextDsdSection.base.start_address);
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

    public void join(Program program)
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
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

    private void joinSection(Program program, List<DsSection> dsSections, String combinedName)
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
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

    public String toString(int indent) {
        String pad = new String(new char[indent]).replace('\0', ' ');
        String pad2 = new String(new char[indent + 2]).replace('\0', ' ');
        String pad4 = new String(new char[indent + 4]).replace('\0', ' ');

        List<String> sections = this.sectionMap
            .entrySet()
            .stream()
            .map(entry -> pad4 + entry.getKey() + ": " + entry.getValue().toString())
            .toList();

        return pad + "DsModule{\n" + pad2 + "name=" + name + ",\n" + pad2 + "sectionMap={\n" +
            String.join(",\n", sections) + "\n" + pad2 + "}\n" + pad + "}";
    }

    @Nullable
    public DsSection getSectionContaining(int address) {
        for (DsSection section : sectionMap.values()) {
            if (section.contains(address)) {
                return section;
            }
        }
        return null;
    }
}
