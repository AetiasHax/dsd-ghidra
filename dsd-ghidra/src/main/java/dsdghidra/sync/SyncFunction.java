package dsdghidra.sync;

import dsdghidra.util.DataTypeUtil;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.bouncycastle.util.Arrays;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.math.BigInteger;

public class SyncFunction {
    public final @NotNull DsdSyncFunction dsdFunction;
    public final @NotNull SymbolName symbolName;
    public final @NotNull Address start;
    public final @NotNull Address end;
    private final @NotNull DsSection dsSection;
    private final @NotNull Program program;
    private final @NotNull AddressSet codeBody;

    public SyncFunction(
        @NotNull Program program,
        @NotNull DsSection dsSection,
        @NotNull DsdSyncFunction dsdFunction
    ) throws InvalidInputException, DuplicateNameException, DsSection.Exception {
        Address start = dsSection.getRequiredAddress(dsdFunction.start);
        Address end = dsSection.getRequiredAddress(dsdFunction.end - 1);

        SymbolName symbolName = new SymbolName(program, dsdFunction.name.getString(), SymbolName.Type.FUNCTION);

        AddressSet codeBody = createCodeBody(start, end, dsdFunction, dsSection);

        this.dsdFunction = dsdFunction;
        this.symbolName = symbolName;
        this.start = start;
        this.end = end;
        this.dsSection = dsSection;
        this.program = program;
        this.codeBody = codeBody;
    }

    private AddressSet createCodeBody(
        @NotNull Address start,
        @NotNull Address end,
        @NotNull DsdSyncFunction dsdFunction,
        @NotNull DsSection dsSection
    ) throws DsSection.Exception {
        AddressSet codeSet = new AddressSet(start, end);
        for (DsdSyncDataRange dataRange : dsdFunction.getDataRanges()) {
            Address rangeStart = dsSection.getRequiredAddress(dataRange.start);
            Address rangeEnd = dsSection.getRequiredAddress(dataRange.end - 1);
            codeSet.deleteRange(rangeStart, rangeEnd);
        }
        return codeSet;
    }

    public @Nullable Function getExistingGhidraFunction() {
        FunctionManager functionManager = program.getFunctionManager();
        return functionManager.getFunctionAt(start);
    }

    public @NotNull Function createGhidraFunction(@NotNull TaskMonitor monitor)
    throws InvalidInputException, DuplicateNameException, CircularDependencyException, OverlappingFunctionException {
        Listing listing = program.getListing();
        listing.clearCodeUnits(start, start.next(), true);

        CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(symbolName.name, start, codeBody,
            SourceType.USER_DEFINED,
            false, true
        );
        createFunctionCmd.applyTo(program, monitor);
        Function function = listing.getFunctionAt(start);
        this.updateGhidraFunction(function);
        return function;
    }

    public void updateGhidraFunction(@NotNull Function function)
    throws InvalidInputException, DuplicateNameException, CircularDependencyException, OverlappingFunctionException {
        function.setName(symbolName.name, SourceType.USER_DEFINED);
        function.setParentNamespace(symbolName.namespace);
        function.setBody(codeBody);
    }

    public boolean ghidraFunctionNeedsUpdate(@NotNull Function function) {
        String ghidraFunctionName = function.getName();
        boolean sameName = ghidraFunctionName.equals(symbolName.name);
        boolean defaultNameBefore = ghidraFunctionName.startsWith("FUN_");
        boolean defaultNameAfter = symbolName.symbol.startsWith("func_");

        if (!sameName && (defaultNameBefore || !defaultNameAfter)) {
            return true;
        }
        if (!function.getParentNamespace().equals(symbolName.namespace)) {
            return true;
        }

        return !function.getBody().equals(codeBody);
    }

    public void definePoolConstants(
        @NotNull FlatProgramAPI api
    ) throws CodeUnitInsertionException, CancelledException, DataTypeUtil.Exception {
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        for (int poolConstant : dsdFunction.pool_constants.getArray()) {
            Address poolAddress = dsSection.getAddress(poolConstant);
            api.clearListing(poolAddress);
            Data data = api.getDataAt(poolAddress);
            if (data == null) {
                data = api.createData(poolAddress, undefined4Type);
            }
            DataTypeUtil.setDataMutability(data, MutabilitySettingsDefinition.CONSTANT);
        }
    }

    public void disassemble(@NotNull Register thumbRegister, @NotNull TaskMonitor monitor) {
        BigInteger thumbModeValue = BigInteger.valueOf(dsdFunction.thumb ? 1L : 0L);
        DisassembleCommand disassembleCommand = new DisassembleCommand(start, null, true);
        disassembleCommand.enableCodeAnalysis(false);
        disassembleCommand.setInitialContext(new RegisterValue(thumbRegister, thumbModeValue));
        disassembleCommand.applyTo(program, monitor);
    }

    public void referPoolConstants(@NotNull FlatProgramAPI api) {
        Listing listing = api.getCurrentProgram().getListing();
        int[] poolConstants = dsdFunction.pool_constants.getArray();

        for (Instruction instruction : listing.getInstructions(new AddressSet(start, end), true)) {
            for (int i = 0; i < instruction.getNumOperands(); ++i) {
                if (instruction.getOperandType(i) != OperandType.SCALAR) {
                    continue;
                }
                for (Object opObject : instruction.getOpObjects(i)) {
                    if (!(opObject instanceof Scalar scalar)) {
                        continue;
                    }
                    int value = (int) scalar.getValue();
                    if (!Arrays.contains(poolConstants, value)) {
                        continue;
                    }
                    Address address = dsSection.getAddress(value);
                    api.createMemoryReference(instruction, i, address, RefType.READ);
                }
            }
        }
    }
}
