package dsdghidra.sync;

import dsdghidra.util.DataTypeUtil;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
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

import java.math.BigInteger;
import java.util.Objects;

public class SyncFunction {
    public final DsdSyncFunction dsdFunction;
    public final SymbolName symbolName;
    public final Address start;
    public final Address end;
    private final DsSection dsSection;
    private final Program program;

    public SyncFunction(Program program, DsSection dsSection, DsdSyncFunction dsdFunction)
    throws InvalidInputException, DuplicateNameException {
        Address start = dsSection.getAddress(dsdFunction.start);
        Address end = dsSection.getAddress(dsdFunction.end - 1);

        Objects.requireNonNull(start);
        Objects.requireNonNull(end);

        SymbolName symbolName = new SymbolName(program, dsdFunction.name.getString(), SymbolName.Type.FUNCTION);

        this.dsdFunction = dsdFunction;
        this.symbolName = symbolName;
        this.start = start;
        this.end = end;
        this.dsSection = dsSection;
        this.program = program;
    }

    public AddressSet getCodeAddressSet() {
        AddressSet codeSet = new AddressSet(start, end);
        for (DsdSyncDataRange dataRange : dsdFunction.getDataRanges()) {
            Address rangeStart = dsSection.getAddress(dataRange.start);
            Address rangeEnd = dsSection.getAddress(dataRange.end - 1);
            codeSet.deleteRange(rangeStart, rangeEnd);
        }
        return codeSet;
    }

    public Function getExistingGhidraFunction() {
        FunctionManager functionManager = program.getFunctionManager();
        return functionManager.getFunctionAt(start);
    }

    public Function createGhidraFunction(TaskMonitor monitor)
    throws InvalidInputException, DuplicateNameException, CircularDependencyException, OverlappingFunctionException {
        Listing listing = program.getListing();
        listing.clearCodeUnits(start, start.next(), true);

        AddressSet body = this.getCodeAddressSet();
        CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(symbolName.name, start, body,
            SourceType.USER_DEFINED,
            false, true
        );
        createFunctionCmd.applyTo(program, monitor);
        Function function = listing.getFunctionAt(start);
        this.updateGhidraFunction(function);
        return function;
    }

    public void updateGhidraFunction(Function function)
    throws InvalidInputException, DuplicateNameException, CircularDependencyException, OverlappingFunctionException {
        function.setName(symbolName.name, SourceType.USER_DEFINED);
        function.setParentNamespace(symbolName.namespace);
        function.setBody(this.getCodeAddressSet());
    }

    public boolean ghidraFunctionNeedsUpdate(Function function) {
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

        AddressSet body = this.getCodeAddressSet();
        if (!function.getBody().equals(body)) {
            return true;
        }

        return false;
    }

    public void definePoolConstants(FlatProgramAPI api)
    throws CodeUnitInsertionException, CancelledException {
        DataType undefined4Type = DataTypeUtil.getUndefined4();

        for (int poolConstant : dsdFunction.pool_constants.getArray()) {
            Address poolAddress = dsSection.getAddress(poolConstant);
            api.clearListing(poolAddress);
            if (api.getDataAt(poolAddress) == null) {
                api.createData(poolAddress, undefined4Type);
            }
        }
    }

    public void disassemble(Register thumbRegister, TaskMonitor monitor) {
        BigInteger thumbModeValue = BigInteger.valueOf(dsdFunction.thumb ? 1L : 0L);
        DisassembleCommand disassembleCommand = new DisassembleCommand(start, null, true);
        disassembleCommand.enableCodeAnalysis(false);
        disassembleCommand.setInitialContext(new RegisterValue(thumbRegister, thumbModeValue));
        disassembleCommand.applyTo(program, monitor);
    }

    public void referPoolConstants(FlatProgramAPI api) {
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
