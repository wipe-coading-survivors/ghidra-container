import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;

// Linearly disassembles the whole primary memory block (data included).
public class ForceDecode extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Address base = prog.getImageBase();
        long size = prog.getMemory().getBlock(base).getSize();
        Address end = base.add(size - 4);
        Disassembler dis = Disassembler.getDisassembler(prog, getMonitor(),
            DisassemblerMessageListener.IGNORE);
        AddressSet range = new AddressSet(base, end);
        AddressSetView done = dis.disassemble(range, null, false);
        long total = 0;
        for (Instruction i : prog.getListing()
            .getInstructions(new AddressSet(base, end), true)) {
            total++;
        }
        println("FORCEDECODE n=" + done.getAddressCountBefore(end)
            + " totalInsns=" + total + " size=" + size);
        println("DONE");
    }
}
