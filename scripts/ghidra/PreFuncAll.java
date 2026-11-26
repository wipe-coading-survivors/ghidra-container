import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class PreFuncAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Address base = prog.getImageBase();
        MemoryBlock block = prog.getMemory().getBlock(base);
        long size = (block == null) ? 0x400000 : block.getSize();
        Function f = prog.getFunctionManager()
                .createFunction("code0", base, new AddressSet(base, base.add(size - 1)),
                                SourceType.USER_DEFINED);
        println("PreFuncAll: created " + f + " body=" + (f == null ? "null" : f.getBody()));
    }
}
