//Imports symbols and relocations from dsd into this Ghidra project.
//@author Aetias
//@category dsd
//@keybinding
//@menupath Analysis.Sync DSD
//@toolbar sync.png

import dialog.DsdConfigChooser;
import dsdghidra.DsdGhidra;
import dsdghidra.DsdGhidraPlugin;
import dsdghidra.sync.*;
import dsdghidra.util.DsdError;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

@SuppressWarnings("unused")
public class SyncDsd extends GhidraScript {
    private boolean dryRun = false;

    private Properties properties;

    private Register thumbRegister;
    private DsModules dsModules;

    @Override
    public AnalysisMode getScriptAnalysisMode() {
        return AnalysisMode.SUSPENDED;
    }

    @Override
    protected void run()
    throws Exception {
        Memory memory = currentProgram.getMemory();
        ProgramContext programContext = currentProgram.getProgramContext();
        this.thumbRegister = programContext.getRegister("TMode");
        this.dsModules = new DsModules(memory);

        loadProperties();

        DsdConfigChooser dsdConfigChooser = new DsdConfigChooser(null, "Begin sync", this.properties);
        File file = dsdConfigChooser.getSelectedFile();
        dsdConfigChooser.dispose();
        if (dsdConfigChooser.wasCancelled()) {
            throw new CancelledException();
        }

        this.properties.setProperty(DsdConfigChooser.LAST_CONFIG_KEY, file.getAbsolutePath());
        saveProperties();

        dryRun = dsdConfigChooser.isDryRun();

        DsdError dsdError = new DsdError();
        DsdSyncData dsdSyncData = new DsdSyncData();
        if (!DsdGhidra.INSTANCE.get_dsd_sync_data(file.getPath(), dsdSyncData, dsdError.memory)) {
            String errorMessage = "Failed to get sync data from dsd-ghidra:\n\n" + dsdError.getString() + "\n";
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
            throw new IOException(errorMessage);
        }

        try {
            this.doSync(dsdSyncData);
        } finally {
            if (!DsdGhidra.INSTANCE.free_dsd_sync_data(dsdSyncData, dsdError.memory)) {
                this.printerr("Failed to free sync data from dsd-ghidra:\n" + dsdError.getString());
            }
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
        }
    }

    private File getProjectLocation() {
        GhidraState state = this.getState();
        Project project = state.getProject();
        ProjectData projectData = project.getProjectData();
        ProjectLocator projectLocator = projectData.getProjectLocator();
        return projectLocator.getProjectDir();
    }

    private File getPropertiesFile() {
        File projectLocation = getProjectLocation();
        Path propertiesPath = Paths.get(projectLocation.getAbsolutePath(), "SyncDsd.properties");
        return propertiesPath.toFile();
    }

    private void loadProperties() {
        File propertiesFile = getPropertiesFile();
        this.properties = new Properties();
        try {
            this.properties.load(new FileInputStream(propertiesFile));
        } catch (IOException ignored) {
        }
    }

    private void saveProperties()
    throws IOException {
        File propertiesFile = getPropertiesFile();
        this.properties.store(new FileOutputStream(propertiesFile), "Properties for the SyncDsd.java script");
    }

    private void doSync(DsdSyncData dsdSyncData) {
        if (!dryRun) {
            this.removeBookmarks();
        }

        this.syncModule(dsdSyncData.arm9, dsModules.main);
        for (DsdSyncAutoload autoload : dsdSyncData.getAutoloads()) {
            switch (autoload.getKind()) {
                case Itcm -> this.syncModule(autoload.module, dsModules.itcm);
                case Dtcm -> this.syncModule(autoload.module, dsModules.dtcm);
                case Unknown -> {
                    DsModule dsModule = dsModules.getAutoload(autoload.index);
                    if (dsModule == null) {
                        printerr(String.format(
                            "No memory blocks for unknown autoload at %08x",
                            autoload.module.base_address
                        ));
                        return;
                    }
                    this.syncModule(autoload.module, dsModule);
                }
            }
        }
        for (DsdSyncOverlay overlay : dsdSyncData.getArm9Overlays()) {
            DsModule dsModule = dsModules.getOverlay(overlay.id);
            if (dsModule == null) {
                printerr(String.format(
                    "No memory blocks for overlay %d",
                    overlay.id
                ));
                return;
            }
            this.syncModule(overlay.module, dsModule);
        }
    }

    private void removeBookmarks() {
        BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
        BookmarkType sectionBookmark = DsdGhidraPlugin.getBookmarkTypeSection();
        BookmarkType delinkFileBookmark = DsdGhidraPlugin.getBookmarkTypeDelinkFile();

        if (sectionBookmark != null) {
            bookmarkManager.removeBookmarks(sectionBookmark.getTypeString());
        }
        if (delinkFileBookmark != null) {
            bookmarkManager.removeBookmarks(delinkFileBookmark.getTypeString());
        }
    }

    private void syncModule(DsdSyncModule dsdSyncModule, @NotNull DsModule dsModule) {
        try {
            this.updateModule(dsdSyncModule, dsModule);
        } catch (Exception e) {
            printerr(String.format(
                "Failed to update module %s, see error:\n%s",
                dsModule.name,
                e
            ));
            return;
        }

        for (DsdSyncSection section : dsdSyncModule.getSections()) {
            if (section.base.isEmpty()) {
                continue;
            }

            DsSection dsSection;
            try {
                dsSection = dsModule.getRequiredSection(section.base);
            } catch (DsModule.Exception e) {
                printerr(e.toString());
                return;
            }

            this.updateSection(dsModule, dsSection);
            for (DsdSyncFunction function : section.getFunctions()) {
                this.updateFunction(function, dsSection);
            }
            for (DsdSyncDataSymbol dataSymbol : section.getSymbols()) {
                this.updateData(dataSymbol, dsSection);
            }
            for (DsdSyncRelocation relocation : section.getRelocations()) {
                this.updateReferences(relocation, dsSection);
            }
        }
        for (DsdSyncDelinkFile file : dsdSyncModule.getFiles()) {
            this.updateDelinkFile(file, dsModule);
        }
    }

    private void updateModule(DsdSyncModule module, DsModule dsModule) {
        SyncModule syncModule = new SyncModule(currentProgram, module, dsModule);

        if (syncModule.needsUpdate()) {
            this.println("Updating sections in module '" + dsModule.name + "'");
            if (!dryRun) {
                try {
                    syncModule.join();
                } catch (Exception e) {
                    printerr(String.format(
                        "Failed to join module %s, see error:\n%s",
                        dsModule.name,
                        e
                    ));
                    return;
                }
                try {
                    syncModule.split();
                } catch (Exception e) {
                    printerr(String.format(
                        "Failed to split module %s, see error:\n%s",
                        dsModule.name,
                        e
                    ));
                    return;
                }
            }
        }
    }

    private void updateSection(DsModule dsModule, DsSection dsSection) {
        SyncSection syncSection = new SyncSection(currentProgram, dsSection, dsModule);

        if (!dryRun) {
            syncSection.addBookmark();
        }
    }

    private void updateDelinkFile(DsdSyncDelinkFile delinkFile, DsModule dsModule) {
        SyncDelinkFile syncDelinkFile = new SyncDelinkFile(currentProgram, delinkFile, dsModule);
        if (!dryRun) {
            try {
                syncDelinkFile.addBookmarks();
            } catch (Exception e) {
                printerr(String.format(
                    "Failed to add bookmarks for delink files in %s",
                    dsModule.name
                ));
                return;
            }
        }
    }

    private void updateFunction(DsdSyncFunction function, DsSection dsSection) {

        SyncFunction syncFunction;
        try {
            syncFunction = new SyncFunction(currentProgram, dsSection, function);
        } catch (Exception e) {
            printerr(String.format(
                "Failed to get function '%s' at %08x in %s, see error:\n%s",
                function.name.getString(),
                function.start,
                dsSection.getModule().name,
                e
            ));
            return;
        }

        Function ghidraFunction = syncFunction.getExistingGhidraFunction();
        if (ghidraFunction == null) {
            String mode = function.thumb ? "thumb" : "arm";
            println("Adding function " + syncFunction.symbolName.symbol + " (" + mode + ") at " + syncFunction.start);

            if (!dryRun) {
                try {
                    ghidraFunction = syncFunction.createGhidraFunction(monitor);
                } catch (Exception e) {
                    printerr(String.format(
                        "Failed to create Ghidra function '%s' at %s in %s, see error:\n%s",
                        syncFunction.symbolName.name,
                        syncFunction.start,
                        dsSection.getModule().name,
                        e
                    ));
                    return;
                }
            }
        } else {
            if (syncFunction.ghidraFunctionNeedsUpdate(ghidraFunction)) {
                println("Updating function " + syncFunction.symbolName.symbol + " at " + syncFunction.start);
                if (!dryRun) {
                    try {
                        syncFunction.updateGhidraFunction(ghidraFunction);
                    } catch (Exception e) {
                        printerr(String.format(
                            "Failed to update Ghidra function '%s' at %s in %s, see error:\n%s",
                            ghidraFunction.getName(),
                            syncFunction.start,
                            dsSection.getModule().name,
                            e
                        ));
                        return;
                    }
                }
            }
        }

        if (!dryRun) {
            try {
                syncFunction.definePoolConstants(this);
            } catch (Exception e) {
                printerr(String.format(
                    "Failed to define pool constants in function '%s' at %s in %s, see error:\n%s",
                    ghidraFunction.getName(),
                    syncFunction.start,
                    dsSection.getModule().name,
                    e
                ));
                return;
            }
            syncFunction.disassemble(thumbRegister, monitor);
            syncFunction.referPoolConstants(this);
        }
    }

    private void updateData(DsdSyncDataSymbol dataSymbol, DsSection dsSection) {
        SyncDataSymbol syncDataSymbol;
        try {
            syncDataSymbol = new SyncDataSymbol(currentProgram, dsSection, dataSymbol);
        } catch (Exception e) {
            printerr(String.format(
                "Failed to get data symbol '%s' at %08x in %s of %s, see error:\n%s",
                dataSymbol.name.getString(),
                dataSymbol.address,
                dsSection.getName(),
                dsSection.getModule().name,
                e
            ));
            return;
        }

        boolean needsUpdate = syncDataSymbol.checkNeedsUpdate();
        String currentName = syncDataSymbol.getCurrentLabel();
        boolean exists = currentName != null;

        if (exists) {
            if (needsUpdate) {
                if (!dryRun) {
                    syncDataSymbol.deleteExistingLabels();
                }
                println("Updating data " + currentName + " at " + syncDataSymbol.address + " to name " +
                    syncDataSymbol.symbolName.symbol);
            } else {
                return;
            }
        } else {
            println("Adding data " + syncDataSymbol.symbolName.symbol + " at " + syncDataSymbol.address);
        }

        if (!dryRun) {
            try {
                syncDataSymbol.createLabel();
            } catch (Exception e) {
                printerr(String.format(
                    "Failed to create data symbol label '%s' at %s in section %s of %s, see error:\n%s",
                    syncDataSymbol.symbolName.name,
                    syncDataSymbol.address,
                    dsSection.getName(),
                    dsSection.getModule().name,
                    e
                ));
            }
            syncDataSymbol.defineData(this);
        }
    }

    private void updateReferences(DsdSyncRelocation relocation, DsSection dsSection) {
        SyncRelocation syncRelocation;
        try {
            syncRelocation = new SyncRelocation(currentProgram, dsSection, relocation);
        } catch (DsSection.Exception e) {
            printerr(String.format(
                "Failed to get relocation from %08x in section %s of %s, see error:\n%s",
                relocation.from,
                dsSection.getName(),
                dsSection.getModule().name,
                e
            ));
            return;
        }

        if (syncRelocation.needsUpdate()) {
            println("Updating references from " + syncRelocation.from);
            if (!dryRun) {
                syncRelocation.deleteExistingReferences();
            }
        } else if (!syncRelocation.existsInGhidra()) {
            println("Adding references from " + syncRelocation.from);
        } else {
            return;
        }

        if (!dryRun) {
            try {
                syncRelocation.addReferences(this, dsModules);
            } catch (Exception e) {
                printerr(String.format(
                    "Failed to add reference from %08x in section %s of %s, see error:\n%s",
                    relocation.from,
                    dsSection.getName(),
                    dsSection.getModule().name,
                    e
                ));
                return;
            }
        }
    }
}
