package dsdghidra.sync;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import dsdghidra.types.UnsafeList;
import dsdghidra.types.UnsafeString;
import dsdghidra.types.UnsafeU32List;

import java.util.List;

public class DsdSyncFunction extends Structure {
    public UnsafeString name;
    public boolean thumb;
    public int start;
    public int end;
    public UnsafeList<DsdSyncDataRange> data_ranges;
    public UnsafeU32List pool_constants;

    public DsdSyncFunction() {
    }

    public DsdSyncFunction(Pointer p) {
        super(p);
        this.read();
    }

    @Override
    protected List<String> getFieldOrder() {
        return List.of("name", "thumb", "start", "end", "data_ranges", "pool_constants");
    }

    public DsdSyncDataRange[] getDataRanges() {
        return data_ranges.getArray(new DsdSyncDataRange[0], DsdSyncDataRange::new);
    }
}
