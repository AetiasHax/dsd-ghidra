package dsdghidra.sync;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;

public class DsModules {
    public final @NotNull DsModule main;
    public final @NotNull DsModule itcm;
    public final @NotNull DsModule dtcm;
    private final @NotNull DsModule[] autoloads;
    private final @NotNull DsModule[] overlays;

    public DsModules(@NotNull Memory memory) {
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

    private static @Nullable String findAutoload(@NotNull List<MemoryBlock> blockList) {
        return findBlock(blockList, "autoload_");
    }

    private static @Nullable String findOverlay(List<MemoryBlock> blockList) {
        return findBlock(blockList, "arm9_ov", "overlay_d_", "overlay_");
    }

    private static @Nullable String findBlock(@NotNull List<MemoryBlock> blockList, @NotNull String... prefixes) {
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

    public static int getOverlayId(@NotNull String moduleName) {
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

    public static int getAutoloadIndex(@NotNull String moduleName) {
        if (!moduleName.startsWith("autoload_")) {
            return -1;
        }

        String addressString = moduleName.substring(9);
        return Integer.parseInt(addressString);
    }

    private static @NotNull DsModule constructModule(
        @NotNull List<MemoryBlock> blockList,
        @NotNull String... moduleNames
    ) {
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
    public @Nullable DsModule getAutoload(int index) {
        if (index < 0 || index >= autoloads.length) {
            return null;
        }
        return autoloads[index];
    }

    public @NotNull DsModule getRequiredAutoload(int index) throws Exception {
        DsModule autoload = getAutoload(index);
        if (autoload == null) {
            throw new DsModules.Exception(String.format(
                "Module for autoload %d not found",
                index
            ));
        }
        return autoload;
    }

    public @Nullable DsModule getOverlay(int id) {
        if (id < 0 || id >= overlays.length) {
            return null;
        }
        return overlays[id];
    }

    public @NotNull DsModule getRequiredOverlay(int id) throws DsModules.Exception {
        DsModule overlay = getOverlay(id);
        if (overlay == null) {
            throw new DsModules.Exception(String.format(
                "Module for overlay %d not found",
                id
            ));
        }
        return overlay;
    }

    public @NotNull String toString(int indent) {
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

    public static final class Exception extends java.lang.Exception {
        public Exception(String message) {
            super(message);
        }
    }
}
