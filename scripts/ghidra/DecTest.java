import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;

// Controlled experiment: disassemble a small window in an undecoded region.
public class DecTest extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Address base = prog.getImageBase();
        Address start = base.add(0x159800L);
        Address stop = base.add(0x15a000L);
        long before = countIns(prog, start, stop);
        Disassembler dis = Disassembler.getDisassembler(prog, getMonitor(),
            DisassemblerMessageListener.IGNORE);
        AddressSet range = new AddressSet(start, stop);
        AddressSetView done = dis.disassemble(range, null, false);
        long after = countIns(prog, start, stop);
        println("DECTEST before=" + before + " after=" + after
            + " doneRange=" + (done.isEmpty() ? "empty"
                : done.getMinAddress() + "-" + done.getMaxAddress()));
        println("DONE");
    }

    long countIns(Program prog, Address a, Address b) {
        AddressSet s = new AddressSet(a, b);
        long n = 0;
        for (Instruction i : prog.getListing().getInstructions(s, true)) {
            n++;
        }
        return n;
    }
}
