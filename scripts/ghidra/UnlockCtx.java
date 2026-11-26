import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

// Context around the unlock read (0x1076f8) + function/caller info for it and the detour fn (0x1d598).
public class UnlockCtx extends GhidraScript {
    void dumpWindow(Program prog, AddressFactory af, long center, int lo, int hi) {
        Address s = af.getDefaultAddressSpace().getAddress(center - lo);
        Address e = af.getDefaultAddressSpace().getAddress(center + hi);
        for (InstructionIterator it = prog.getListing().getInstructions(new AddressSet(s, e), true);
             it.hasNext(); ) {
            Instruction i = it.next();
            String mark = (i.getAddress().getOffset() == center) ? "  <<< UNLOCK-READ" : "";
            StringBuilder refs = new StringBuilder();
            for (Reference r : prog.getReferenceManager().getReferencesFrom(i.getAddress()))
                refs.append(" ->0x").append(Long.toHexString(r.getToAddress().getOffset())).append(' ');
            println("  " + Long.toHexString(i.getAddress().getOffset()) + "  " + i.toString()
                + (refs.length() > 0 ? "  [REF" + refs + "]" : "") + mark);
        }
    }
    void fnInfo(Program prog, AddressFactory af, long a, String label) {
        Address addr = af.getDefaultAddressSpace().getAddress(a);
        Function f = prog.getFunctionManager().getFunctionContaining(addr);
        if (f == null) { println(label + " 0x" + Long.toHexString(a) + " fn=<none>"); return; }
        long entry = f.getEntryPoint().getOffset();
        println(label + " 0x" + Long.toHexString(a)
            + " fn=" + f.getName() + " entry=0x" + Long.toHexString(entry)
            + " body=" + f.getBody().getMinAddress().getOffset()
            + ".." + f.getBody().getMaxAddress().getOffset());
        for (Reference r : prog.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
            Address from = r.getFromAddress();
            Instruction fi = prog.getListing().getInstructionAt(from);
            println("    CALLER from=0x" + Long.toHexString(from.getOffset())
                + " type=" + r.getReferenceType() + " ins=" + (fi == null ? "?" : fi.toString()));
        }
    }
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        println("=== fn info: unlock-read @0x1076f8 ===");
        fnInfo(prog, af, 0x1076f8L, "UNLOCKFN");
        println("=== fn info: detour @0x1d598 ===");
        fnInfo(prog, af, 0x1d598L, "DETOURFN");
        println("=== window around unlock read 0x1076f8 (0x1076b0..0x107760) ===");
        dumpWindow(prog, af, 0x1076f8L, 0x48, 0x68);
        println("DONE");
    }
}
