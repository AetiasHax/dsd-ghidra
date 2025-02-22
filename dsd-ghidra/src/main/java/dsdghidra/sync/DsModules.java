package dsdghidra.sync;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class DsModules {
    public final DsModule main;
    public final DsModule itcm;
    public final DsModule dtcm;
    private final Map<Integer, DsModule> autoloads;
    private final DsModule[] overlays;

    public DsModules(Memory memory) {
        List<MemoryBlock> blockList = new ArrayList<>();
        Collections.addAll(blockList, memory.getBlocks());

        DsModule main = constructModule(blockList, "arm9_main");
        DsModule itcm = constructModule(blockList, "itcm");
        DsModule dtcm = constructModule(blockList, "dtcm");

        List<DsModule> overlayList = new ArrayList<>();
        String overlayModuleName;
        while ((overlayModuleName = findOverlay(blockList)) != null) {
            int overlayId = getOverlayId(overlayModuleName);
            while (overlayList.size() < overlayId + 1) {
                overlayList.add(null);
            }

            DsModule overlay = constructModule(blockList, overlayModuleName);
            overlayList.set(overlayId, overlay);
        }

        Map<Integer, DsModule> autoloadMap = new HashMap<>();
        String autoloadModuleName;
        while ((autoloadModuleName = findAutoload(blockList)) != null) {
            int baseAddress = getAutoloadBaseAddress(autoloadModuleName);
            DsModule autoload = constructModule(blockList, autoloadModuleName);
            autoloadMap.put(baseAddress, autoload);
        }

        this.main = main;
        this.itcm = itcm;
        this.dtcm = dtcm;
        this.autoloads = autoloadMap;
        this.overlays = overlayList.toArray(new DsModule[0]);
    }

    private static String findAutoload(List<MemoryBlock> blockList) {
        return findBlock(blockList, "autoload_");
    }

    private static String findOverlay(List<MemoryBlock> blockList) {
        return findBlock(blockList, "arm9_ov");
    }

    private static String findBlock(List<MemoryBlock> blockList, String prefix) {
        for (MemoryBlock block : blockList) {
            String blockName = block.getName();
            if (!blockName.startsWith(prefix)) {
                continue;
            }

            int sectionStartIndex = blockName.indexOf('.');
            if (sectionStartIndex >= 0) {
                return blockName.substring(sectionStartIndex);
            }

            return blockName;
        }
        return null;
    }

    private static int getOverlayId(String moduleName) {
        if (!moduleName.startsWith("arm9_ov")) {
            return -1;
        }

        String overlayIdString = moduleName.substring(7);
        ;
        return Integer.parseInt(overlayIdString, 10);
    }

    private static int getAutoloadBaseAddress(String moduleName) {
        if (!moduleName.startsWith("autoload_")) {
            return -1;
        }

        String addressString = moduleName.substring(9);
        return Integer.parseInt(addressString, 16);
    }

    private static DsModule constructModule(List<MemoryBlock> blockList, String moduleName) {
        DsModule module = new DsModule(moduleName);
        for (int i = blockList.size() - 1; i >= 0; i--) {
            MemoryBlock block = blockList.get(i);
            String blockName = block.getName();

            if (!blockName.startsWith(moduleName)) {
                continue;
            }

            DsSection section;
            int sectionStartIndex = blockName.indexOf('.');
            if (sectionStartIndex >= 0) {
                String sectionName = blockName.substring(sectionStartIndex);
                section = new DsSection(sectionName, block);
            } else {
                section = new DsSection(DsModule.COMBINED_CODE_KEY, block);
            }

            module.addSection(section);
            blockList.remove(i);
        }
        return module;
    }

    /**
     * Gets an autoload module other than ITCM and DTCM.
     */
    public DsModule getAutoload(int baseAddress) {
        return autoloads.get(baseAddress);
    }

    public DsModule getOverlay(int id) {
        if (id < 0 || id >= overlays.length) {
            return null;
        }
        return overlays[id];
    }

    public String toString(int indent) {
        String pad = new String(new char[indent]).replace('\0', ' ');
        String pad2 = new String(new char[indent + 2]).replace('\0', ' ');
        String pad4 = new String(new char[indent + 4]).replace('\0', ' ');

        List<String> autoloads = this
            .autoloads
            .entrySet()
            .stream()
            .map(entry -> pad4 + Integer.toHexString(entry.getKey()) + ": " + entry.getValue().toString(indent + 4))
            .toList();
        List<String> overlays = Arrays
            .stream(this.overlays)
            .map(overlay -> overlay.toString(indent + 4))
            .toList();

        return pad + "DsModules{\n" +
            pad2 + "main=" + main.toString(indent + 2) + ",\n" +
            pad2 + "itcm=" + itcm.toString(indent + 2) + ",\n" +
            pad2 + "dtcm=" + dtcm.toString(indent + 2) + ",\n" +
            pad2 + "autoloads={\n" + String.join(",\n", autoloads) + "\n" +
            pad2 + "},\n" +
            pad2 + "overlays=[\n" + String.join(",\n", overlays) + "\n" +
            pad2 + "]\n" +
            pad + '}';
    }

    public static boolean isMain(String addressSpaceName) {
        return addressSpaceName.equals("arm9_main") ||
            addressSpaceName.equals("arm9_main.bss") ||
            addressSpaceName.equals("ARM9_Main_Memory") ||
            addressSpaceName.equals("ARM9_Main_Memory_bss");
    }

    public static boolean isItcm(String addressSpaceName) {
        return addressSpaceName.equals("itcm") ||
            addressSpaceName.equals("ITCM");
    }

    public static boolean isDtcm(String addressSpaceName) {
        return addressSpaceName.equals("dtcm") ||
            addressSpaceName.equals("dtcm.bss") ||
            addressSpaceName.equals("DTCM") ||
            addressSpaceName.equals("DTCM_bss");
    }

    public static int parseOverlayNumber(String blockName) {
        if (!blockName.startsWith("arm9_ov")) {
            return -1;
        }

        int sectionStartIndex = blockName.indexOf('.');
        String overlayNumberString;
        if (sectionStartIndex >= 0) {
            overlayNumberString = blockName.substring(7, sectionStartIndex);
        } else {
            overlayNumberString = blockName.substring(7);
        }

        return Integer.parseInt(overlayNumberString, 10);
    }
}
