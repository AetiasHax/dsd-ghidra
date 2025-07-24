package dsdghidra.dsd;

import ghidra.program.model.symbol.RefType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public enum DsdRelocationKind {
    ArmCall,
    ThumbCall,
    ArmCallThumb,
    ThumbCallArm,
    ArmBranch,
    Load;

    public static final @NotNull DsdRelocationKind[] VALUES = DsdRelocationKind.values();

    public @Nullable RefType getRefType(boolean conditional) {
        switch (this) {
            case ArmCall, ThumbCall, ArmCallThumb, ThumbCallArm -> {
                return conditional ? RefType.CONDITIONAL_CALL : RefType.UNCONDITIONAL_CALL;
            }
            case ArmBranch -> {
                return conditional ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
            }
            case Load -> {
                return RefType.DATA;
            }
        }
        return null;
    }
}
