/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dsdghidra;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import docking.widgets.OptionDialog;
import docking.widgets.OptionDialogBuilder;
import dsdghidra.loader.DsIoRegister;
import dsdghidra.loader.DsLoaderModule;
import dsdghidra.loader.DsMemoryRegion;
import dsdghidra.loader.DsRomLoaderData;
import dsdghidra.util.DsdError;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Uses dsd to load a DS ROM into a Ghidra project.
 */
@SuppressWarnings("unused")
public class DsRomLoader extends AbstractProgramWrapperLoader {

    @Override
    public String getName() {
        // Name the loader. This name must match the name of the loader in the .opinion
        // files.
        return "dsd-ghidra-loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        byte[] bytes = provider.readBytes(0, provider.length());
        if (DsdGhidra.INSTANCE.is_valid_ds_rom(bytes, bytes.length)) {
            LanguageCompilerSpecPair languageCompiler = new LanguageCompilerSpecPair("ARM:LE:32:v5t", "default");
            LoadSpec loadSpec = new LoadSpec(this, 0, languageCompiler, true);
            return List.of(loadSpec);
        }
        return List.of();
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
        TaskMonitor monitor, MessageLog log
    ) throws CancelledException, IOException {
        byte[] bytes = provider.readBytes(0, provider.length());
        DsdError dsdError = new DsdError();
        DsRomLoaderData data = new DsRomLoaderData();
        if (!DsdGhidra.INSTANCE.get_loader_data(bytes, bytes.length, data, dsdError.memory)) {
            String errorMessage = "Failed to get ROM data from dsd-ghidra:\n\n" + dsdError.getString() + "\n";
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
            throw new IOException(errorMessage);
        }

        OptionDialogBuilder dialogBuilder = new OptionDialogBuilder();
        dialogBuilder.setTitle("Choose CPU program");
        dialogBuilder.setMessage("Which CPU program do you want to load?");
        dialogBuilder.addCancel();
        dialogBuilder.addOption("ARM7");
        dialogBuilder.addOption("ARM9");

        int cpuOption = dialogBuilder.show();
        if (cpuOption == OptionDialog.CANCEL_OPTION) {
            throw new CancelledException("User clicked cancel");
        }

        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        try {
            if (cpuOption == 1) {
                createArm7(data, api);
            } else if (cpuOption == 2) {
                createArm9(data, api);
            } else {
                throw new CancelledException("Invalid CPU program");
            }
        } catch (CreateMemoryBlockFailedException | CreateLabelFailedException e) {
            throw new IOException(e.getMessage());
        } finally {
            if (!DsdGhidra.INSTANCE.free_loader_data(data, dsdError.memory)) {
                log.appendMsg("Failed to free ROM data from dsd-ghidra:\n" + dsdError.getString());
            }
            DsdGhidra.INSTANCE.free_error(dsdError.memory);
        }
    }

    private static void createArm9(DsRomLoaderData data, FlatProgramAPI api)
    throws CancelledException, CreateMemoryBlockFailedException, CreateLabelFailedException {
        try {
            data.arm9.createBlock(api);
            for (DsLoaderModule autoload : data.getAutoloads()) {
                autoload.createBlock(api);
            }
            for (DsLoaderModule overlay : data.getArm9Overlays()) {
                overlay.createOverlayBlock(api);
            }
            for (DsMemoryRegion region : DsMemoryRegion.ARM9_REGIONS) {
                region.createBlock(api);
            }
        } catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
            throw new CreateMemoryBlockFailedException(e);
        }

        try {
            for (DsIoRegister register : DsIoRegister.ARM9_REGS) {
                api.createLabel(api.toAddr(register.address), register.name, true);
            }
        } catch (Exception e) {
            throw new CreateLabelFailedException(e);
        }
    }

    private static void createArm7(DsRomLoaderData data, FlatProgramAPI api)
    throws CancelledException, CreateMemoryBlockFailedException, CreateLabelFailedException {
        try {
            data.arm7.createBlock(api);
            for (DsLoaderModule overlay : data.getArm7Overlays()) {
                overlay.createOverlayBlock(api);
            }
            for (DsMemoryRegion region : DsMemoryRegion.ARM7_REGIONS) {
                region.createBlock(api);
            }
        } catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
            throw new CreateMemoryBlockFailedException(e);
        }

        try {
            for (DsIoRegister register : DsIoRegister.ARM7_REGS) {
                api.createLabel(api.toAddr(register.address), register.name, true);
            }
        } catch (Exception e) {
            throw new CreateLabelFailedException(e);
        }
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
        boolean isLoadIntoProgram
    ) {
        return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        return super.validateOptions(provider, loadSpec, options, program);
    }

    private static class CreateLabelFailedException extends Exception {
        public CreateLabelFailedException(Throwable cause) {
            super(cause);
        }
    }

    private static class CreateMemoryBlockFailedException extends Exception {
        public CreateMemoryBlockFailedException(Throwable cause) {
            super(cause);
        }
    }
}

