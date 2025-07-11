package dsdghidra.loader;

import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;

public class DsMemoryRegion {
    public static final DsMemoryRegion[] ARM9_REGIONS = {
        new DsMemoryRegion(0x03000000, 0x03004000, "swram"),
        new DsMemoryRegion(0x04000000, 0x04005000, "io"),
        new DsMemoryRegion(0x04100000, 0x04100020, "io_read"),
        new DsMemoryRegion(0x05000000, 0x05000800, "palettes"),
        new DsMemoryRegion(0x06000000, 0x06080000, "vram_bg"),
        new DsMemoryRegion(0x06200000, 0x06220000, "vram_bg_sub"),
        new DsMemoryRegion(0x06400000, 0x06440000, "vram_obj"),
        new DsMemoryRegion(0x06600000, 0x06620000, "vram_obj_sub"),
        new DsMemoryRegion(0x06800000, 0x06840000, "vram_lcdc"),
        new DsMemoryRegion(0x07000000, 0x07000800, "oam"),
        new DsMemoryRegion(0x08000000, 0x0a000000, "gba_rom"),
        new DsMemoryRegion(0x0a000000, 0x0a010000, "gba_ram"),
    };

    public static final DsMemoryRegion[] ARM7_REGIONS = {
        new DsMemoryRegion(0x03000000, 0x03004000, "swram"),
        new DsMemoryRegion(0x03800000, 0x03808000, "wram"),
        new DsMemoryRegion(0x04000000, 0x04001000, "io"),
        new DsMemoryRegion(0x04800000, 0x04810000, "wifi"),
        new DsMemoryRegion(0x06000000, 0x06040000, "vram"),
        new DsMemoryRegion(0x08000000, 0x0a000000, "gba_rom"),
        new DsMemoryRegion(0x0a000000, 0x0a010000, "gba_ram"),
    };

    public final int start;
    public final int end;
    public final String name;

    public DsMemoryRegion(int start, int end, String name) {
        this.start = start;
        this.end = end;
        this.name = name;
    }

    public int size() {
        return this.end - this.start;
    }

    public void createBlock(FlatProgramAPI api)
    throws AddressOverflowException, LockException, MemoryConflictException {
        Program program = api.getCurrentProgram();
        Memory memory = program.getMemory();
        Address address = api.toAddr(this.start);
        MemoryBlock block = memory.createUninitializedBlock(this.name, address, this.size(), false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
    }
}
