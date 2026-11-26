import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;

public class PreFunc extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Address base = prog.getImageBase();
        AddressSet body = new AddressSet(base, base.add(0x400000));
        Function f = prog.getFunctionManager()
                .createFunction("code0", base, body, SourceType.USER_DEFINED);
        println("PreFunc: created " + f + " body=" + (f == null ? "null" : f.getBody()));
    }
}
