package dsdghidra.sync;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class DsModules {
    public final DsModule main;
    public final DsModule itcm;
    public final DsModule dtcm;
    private final DsModule[] autoloads;
    private final DsModule[] overlays;

    public DsModules(Memory memory) {
        List<MemoryBlock> blockList = new ArrayList<>();
        Collections.addAll(blockList, memory.getBlocks());

        DsModule main = constructModule(blockList, "arm9_main", "ARM9_Main_Memory");
        DsModule itcm = constructModule(blockList, "itcm", "ITCM");
        DsModule dtcm = constructModule(blockList, "dtcm", "DTCM");

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

        List<DsModule> autoloadList = new ArrayList<>();
        String autoloadModuleName;
        while ((autoloadModuleName = findAutoload(blockList)) != null) {
            int autoloadIndex = getAutoloadIndex(autoloadModuleName);
            while (autoloadList.size() < autoloadIndex + 1) {
                autoloadList.add(null);
            }

            DsModule autoload = constructModule(blockList, autoloadModuleName);
            autoloadList.set(autoloadIndex, autoload);
        }

        this.main = main;
        this.itcm = itcm;
        this.dtcm = dtcm;
        this.autoloads = autoloadList.toArray(new DsModule[0]);
        this.overlays = overlayList.toArray(new DsModule[0]);
    }

    private static String findAutoload(List<MemoryBlock> blockList) {
        return findBlock(blockList, "autoload_");
    }

    private static String findOverlay(List<MemoryBlock> blockList) {
        return findBlock(blockList, "arm9_ov", "overlay_d_", "overlay_");
    }

    private static String findBlock(List<MemoryBlock> blockList, String... prefixes) {
        for (MemoryBlock block : blockList) {
            String blockName = block.getName();

            boolean found = false;
            for (String prefix : prefixes) {
                if (blockName.startsWith(prefix)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                continue;
            }

            int sectionStartIndex = blockName.indexOf('.');
            if (sectionStartIndex >= 0) {
                return blockName.substring(0, sectionStartIndex);
            }

            return blockName;
        }
        return null;
    }

    public static int getOverlayId(String moduleName) {
        String overlayIdString = null;
        if (moduleName.startsWith("arm9_ov")) {
            overlayIdString = moduleName.substring(7);
        } else if (moduleName.startsWith("overlay_d_")) {
            overlayIdString = moduleName.substring(10);
        } else if (moduleName.startsWith("overlay_")) {
            overlayIdString = moduleName.substring(8);
        }

        if (overlayIdString == null) {
            return -1;
        }

        return Integer.parseInt(overlayIdString, 10);
    }

    public static int getAutoloadIndex(String moduleName) {
        if (!moduleName.startsWith("autoload_")) {
            return -1;
        }

        String addressString = moduleName.substring(9);
        return Integer.parseInt(addressString);
    }

    private static DsModule constructModule(List<MemoryBlock> blockList, String... moduleNames) {
        DsModule module = new DsModule(moduleNames[0]);
        for (int i = blockList.size() - 1; i >= 0; i--) {
            MemoryBlock block = blockList.get(i);
            String blockName = block.getName();

            int sectionStartIndex = blockName.indexOf('.');
            String blockBaseName;
            String sectionName;
            if (sectionStartIndex >= 0) {
                blockBaseName = blockName.substring(0, sectionStartIndex);
                sectionName = blockName.substring(sectionStartIndex);
            } else {
                blockBaseName = blockName;
                sectionName = DsModule.COMBINED_CODE_KEY;
            }

            boolean found = false;
            for (String moduleName : moduleNames) {
                if (blockBaseName.equals(moduleName)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                continue;
            }

            DsSection section = new DsSection(sectionName, module, block);
            module.addSection(section);
            blockList.remove(i);
        }
        return module;
    }

    /**
     * Gets an autoload module other than ITCM and DTCM.
     */
    public DsModule getAutoload(int index) {
        if (index < 0 || index >= autoloads.length) {
            return null;
        }
        return autoloads[index];
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

        List<String> autoloads = Arrays
            .stream(this.autoloads)
            .map(autoload -> autoload.toString(indent + 4))
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
}
