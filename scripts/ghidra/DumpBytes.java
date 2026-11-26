import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

// Dumps raw bytes of a range (lo hi in /work/build/ghidra-range.txt, else first 0x100 bytes).
public class DumpBytes extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Memory mem = prog.getMemory();
        AddressFactory af = prog.getAddressFactory();
        Address lo = af.getAddress("0");
        Address hi = af.getAddress("0x100");
        Path p = Paths.get("/work/build/ghidra-range.txt");
        if (Files.exists(p)) {
            String[] t = Files.readString(p).trim().split("\\s+");
            lo = af.getAddress(t[0]);
            hi = af.getAddress(t[1]);
        }
        long start = lo.getOffset();
        long end = hi.getOffset();
        long n = end - start;
        if (n > 0x20000) n = 0x20000;
        byte[] buf = new byte[(int) n];
        try {
            mem.getBytes(af.getAddress("0x" + Long.toHexString(start)), buf);
        } catch (MemoryAccessException e) {
            println("MEMERR " + e.getMessage());
            println("DONE");
            return;
        }
        for (int i = 0; i < buf.length; i += 16) {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%08x: ", start + i));
            for (int j = i; j < i + 16 && j < buf.length; j++) {
                sb.append(String.format("%02x ", buf[j]));
            }
            println(sb.toString());
        }
        println("SIZE " + buf.length);
        println("DONE");
    }
}
