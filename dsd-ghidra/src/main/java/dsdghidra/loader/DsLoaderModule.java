package dsdghidra.loader;

import java.io.ByteArrayInputStream;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import dsdghidra.types.UnsafeString;
import dsdghidra.types.UnsafeU8List;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.annotations.NotNull;

public class DsLoaderModule extends Structure {
    public UnsafeU8List bytes;
    public int base_address;
    public int bss_size;
    public UnsafeString name;

    public DsLoaderModule() {
        super();
    }

    public DsLoaderModule(@NotNull Pointer pointer) {
        super(pointer);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("bytes", "base_address", "bss_size", "name");
    }

    public static class ByReference extends DsLoaderModule implements Structure.ByReference {
    }

    public byte[] getBytes() {
        return this.bytes.getArray();
    }

    public @NotNull String getName() {
        return this.name.getString();
    }

    public void createBlock(
        @NotNull FlatProgramAPI api
    ) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException {
        this.createBlock(api, false);
    }

    public void createOverlayBlock(
        @NotNull FlatProgramAPI api
    ) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException {
        this.createBlock(api, true);
    }

    private void createBlock(
        @NotNull FlatProgramAPI api,
        boolean overlay
    ) throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException {
        Program program = api.getCurrentProgram();
        TaskMonitor monitor = api.getMonitor();
        Memory memory = program.getMemory();
        Address baseAddress = api.toAddr(this.base_address);

        if (this.bytes.len > 0) {
            MemoryBlock block = memory.createInitializedBlock(this.getName(), baseAddress,
                    new ByteArrayInputStream(this.getBytes()), this.bytes.len, monitor, overlay);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(true);
        }

        if (this.bss_size > 0) {
            Address bssAddress = baseAddress.add(this.bytes.len);
            MemoryBlock bssBlock = memory.createUninitializedBlock(this.getName() + ".bss", bssAddress, this.bss_size, overlay);
            bssBlock.setRead(true);
            bssBlock.setWrite(true);
            bssBlock.setExecute(false);
        }
    }
}
