package dsdghidra.sync;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class SyncDataSymbol {
    public final @NotNull DsdSyncDataSymbol dsdDataSymbol;
    public final @NotNull SymbolName symbolName;
    public final @NotNull DsSection dsSection;
    public final @NotNull Address address;
    private final @NotNull Program program;

    public SyncDataSymbol(
        @NotNull Program program,
        @NotNull DsSection dsSection,
        @NotNull DsdSyncDataSymbol dsdDataSymbol
    ) throws InvalidInputException, DuplicateNameException, DsSection.Exception {
        SymbolName symbolName = new SymbolName(program, dsdDataSymbol.name.getString(), SymbolName.Type.OTHER);
        Address address = dsSection.getRequiredAddress(dsdDataSymbol.address);

        this.dsdDataSymbol = dsdDataSymbol;
        this.symbolName = symbolName;
        this.dsSection = dsSection;
        this.address = address;
        this.program = program;
    }

    public @Nullable String getCurrentLabel() {
        SymbolTable symbolTable = program.getSymbolTable();
        for (Symbol existingSymbol : symbolTable.getSymbols(address)) {
            if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                return existingSymbol.getName();
            }
        }
        return null;
    }

    public boolean checkNeedsUpdate() {
        SymbolTable symbolTable = program.getSymbolTable();
        boolean defaultName = symbolName.symbol.startsWith("data_");
        for (Symbol existingSymbol : symbolTable.getSymbols(address)) {
            if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                if (!existingSymbol.getParentNamespace().equals(symbolName.namespace)) {
                    return true;
                }

                String currentName = existingSymbol.getName();
                boolean sameName = currentName.equals(symbolName.name);
                boolean importantCurrentName = currentName.startsWith("s_") || currentName.startsWith(
                    "PTR_s_") || currentName.startsWith(
                    "u_") || currentName.startsWith("vtable_");
                if (sameName) {
                    continue;
                }
                if (!importantCurrentName || !defaultName) {
                    return true;
                }
            }
        }
        return false;
    }

    public void deleteExistingLabels() {
        SymbolTable symbolTable = program.getSymbolTable();
        for (Symbol existingSymbol : symbolTable.getSymbols(address)) {
            if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                existingSymbol.delete();
            }
        }
    }

    public void createLabel() throws InvalidInputException {
        SymbolTable symbolTable = program.getSymbolTable();
        symbolTable.createLabel(address, symbolName.name, symbolName.namespace, SourceType.USER_DEFINED);
    }

    public void defineData(@NotNull FlatProgramAPI api) {
        DsdSyncDataKind kind = dsdDataSymbol.getKind();
        if (kind.isDefined()) {
            DataType dataType = kind.asDataType();
            if (dataType != null) {
                try {
                    if (dsdDataSymbol.count != 1) {
                        api.createData(address, new ArrayDataType(dataType, dsdDataSymbol.count));
                    } else {
                        api.createData(address, dataType);
                    }
                } catch (CodeUnitInsertionException ignore) {
                }
            }
        }
    }
}
