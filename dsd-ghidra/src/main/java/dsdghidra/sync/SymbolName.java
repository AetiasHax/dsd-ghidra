package dsdghidra.sync;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class SymbolName {
    public final String symbol;
    public final Namespace namespace;
    public final String name;

    public SymbolName(Program program, String symbol, Type type)
            throws InvalidInputException, DuplicateNameException {
        String withoutParams = symbol;
        if (type == Type.FUNCTION) {
            int parenIndex = symbol.indexOf('(');
            if (parenIndex >= 0) {
                withoutParams = symbol.substring(0, parenIndex);
            }
        }

        String[] namespaces = withoutParams.split("::");
        String name = namespaces[namespaces.length - 1].replace(' ', '_');

        Namespace namespace = this.getOrCreateNamespace(program, namespaces);

        this.symbol = symbol;
        this.namespace = namespace;
        this.name = name;
    }

    public static enum Type {
        FUNCTION,
        OTHER,
    }

    private Namespace getOrCreateNamespace(Program program, String[] namespaces)
            throws InvalidInputException, DuplicateNameException {
        SymbolTable symbolTable = program.getSymbolTable();

        Namespace parent = program.getGlobalNamespace();
        for (int i = 0; i < namespaces.length - 1; i++) {
            parent = symbolTable.getOrCreateNameSpace(parent, namespaces[i], SourceType.USER_DEFINED);
        }
        return parent;
    }
}
