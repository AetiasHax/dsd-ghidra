package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DsdSyncSection extends Structure {
    public DsdSyncBaseSection base;
    public UnsafeList<DsdSyncFunction> functions;
    public UnsafeList<DsdSyncDataSymbol> symbols;
    public UnsafeList<DsdSyncRelocation> relocations;

    public DsdSyncSection() {
        super();
    }

    public DsdSyncSection(@NotNull Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected @NotNull List<String> getFieldOrder() {
        return List.of("base", "functions", "symbols", "relocations");
    }

    public @NotNull DsdSyncFunction[] getFunctions() {
        return functions.getArray(new DsdSyncFunction[0], DsdSyncFunction::new);
    }

    public @NotNull DsdSyncDataSymbol[] getSymbols() {
        return symbols.getArray(new DsdSyncDataSymbol[0], DsdSyncDataSymbol::new);
    }

    public @NotNull DsdSyncRelocation[] getRelocations() {
        return relocations.getArray(new DsdSyncRelocation[0], DsdSyncRelocation::new);
    }
}
