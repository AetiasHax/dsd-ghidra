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
import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

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

    private void doSync(DsdSyncData dsdSyncData)
    throws Exception {
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
                        throw new Exception("No memory blocks for unknown autoload at base address " +
                            Integer.toHexString(autoload.module.base_address));
                    }
                    this.syncModule(autoload.module, dsModule);
                }
            }
        }
        for (DsdSyncOverlay overlay : dsdSyncData.getArm9Overlays()) {
            DsModule dsModule = dsModules.getOverlay(overlay.id);
            if (dsModule == null) {
                throw new Exception("No memory blocks for overlay " + overlay.id);
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

    private void syncModule(DsdSyncModule dsdSyncModule, DsModule dsModule)
    throws Exception {
        this.updateModule(dsdSyncModule, dsModule);

        for (DsdSyncSection section : dsdSyncModule.getSections()) {
            if (section.base.isEmpty()) {
                continue;
            }

            DsSection dsSection = dsModule.getSection(section.base);
            if (dsSection == null) {
                throw new Exception("Failed to find section '" + section.base.name.getString() + "' in module '" + dsModule.name + "'");
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

    private void updateModule(DsdSyncModule module, DsModule dsModule)
    throws LockException, MemoryBlockException, NotFoundException, ExclusiveCheckoutException {
        SyncModule syncModule = new SyncModule(currentProgram, module, dsModule);

        if (syncModule.needsUpdate()) {
            this.println("Updating sections in module '" + dsModule.name + "'");
            if (!dryRun) {
                syncModule.join();
                syncModule.split();
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
            syncDelinkFile.addBookmarks();
        }
    }

    private void updateFunction(DsdSyncFunction function, DsSection dsSection)
    throws
        InvalidInputException,
        DuplicateNameException,
        CodeUnitInsertionException,
        CircularDependencyException,
        OverlappingFunctionException,
        CancelledException {

        SyncFunction syncFunction = new SyncFunction(currentProgram, dsSection, function);

        Function ghidraFunction = syncFunction.getExistingGhidraFunction();
        if (ghidraFunction == null) {
            String mode = function.thumb ? "thumb" : "arm";
            println("Adding function " + syncFunction.symbolName.symbol + " (" + mode + ") at " + syncFunction.start);

            if (!dryRun) {
                syncFunction.createGhidraFunction(monitor);
            }
        } else {
            if (syncFunction.ghidraFunctionNeedsUpdate(ghidraFunction)) {
                println("Updating function " + syncFunction.symbolName.symbol + " at " + syncFunction.start);
                if (!dryRun) {
                    try {
                        syncFunction.updateGhidraFunction(ghidraFunction);
                    } catch (OverlappingFunctionException e) {
                        this.printerr("Failed to update function size: " + e.getMessage());
                    }
                }
            }
        }

        if (!dryRun) {
            syncFunction.definePoolConstants(this);
            syncFunction.disassemble(thumbRegister, monitor);
            syncFunction.referPoolConstants(this);
        }
    }

    private void updateData(DsdSyncDataSymbol dataSymbol, DsSection dsSection)
    throws InvalidInputException, DuplicateNameException {
        SyncDataSymbol syncDataSymbol = new SyncDataSymbol(currentProgram, dsSection, dataSymbol);

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
            syncDataSymbol.createLabel();
            syncDataSymbol.defineData(this);
        }
    }

    private void updateReferences(DsdSyncRelocation relocation, DsSection dsSection) {
        SyncRelocation syncRelocation = new SyncRelocation(currentProgram, dsSection, relocation);

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
            syncRelocation.addReferences(this, dsModules);
        }
    }
}
