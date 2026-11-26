import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Scans all decoded instructions for immediate operands matching target hex values.
// Matches on the disassembly string with hex-boundary guards (no Operand API in Ghidra 12).
// Target set: /work/build/ghidra-scan.txt, one hex value per line, # comments.
public class ScanImms extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Path p = Paths.get("/work/build/ghidra-scan.txt");
        if (!Files.exists(p)) { println("ERROR no " + p); println("DONE"); return; }
        Map<String, Pattern> pats = new HashMap<>();
        for (String line : Files.readAllLines(p)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String hs = line;
            if (hs.startsWith("0x") || hs.startsWith("0X")) hs = hs.substring(2);
            Pattern pat = Pattern.compile(
                "(?i)(?<![0-9a-fr])" + hs + "(?![0-9a-f])");
            pats.put(hs, pat);
        }
        int hits = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            String s = ins.toString();
            StringBuilder matched = null;
            for (Map.Entry<String, Pattern> e : pats.entrySet()) {
                Matcher m = e.getValue().matcher(s);
                if (m.find()) {
                    if (matched == null) matched = new StringBuilder();
                    matched.append("0x").append(e.getKey()).append(' ');
                }
            }
            if (matched == null) continue;
            Function fn = prog.getFunctionManager().getFunctionContaining(ins.getAddress());
            String fns = (fn == null) ? "<none>" : fn.getEntryPoint().toString();
            String bytes = "";
            try {
                byte[] b = ins.getParsedBytes();
                for (byte x : b) bytes += String.format("%02x ", x);
            } catch (Exception ex) { bytes = "?"; }
            println("HIT 0x" + Long.toHexString(ins.getAddress().getOffset())
                + " imm=" + matched.toString().trim()
                + " fn=" + fns
                + " bytes=" + bytes.trim()
                + " | " + s);
            hits++;
        }
        println("NHIT " + hits);
        println("DONE");
    }
}
