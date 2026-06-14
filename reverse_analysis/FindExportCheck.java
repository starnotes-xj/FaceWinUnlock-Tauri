import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class FindExportCheck extends GhidraScript {
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var mem = program.getMemory();
        
        // 1. 找到 "KspExportKey" 字符串
        var addr = findString("KspExportKey");
        if (addr != null) {
            println("KspExportKey found at: " + addr);
            // 找交叉引用
            var refs = getReferencesTo(addr);
            for (var ref : refs) {
                println("  Referenced by: " + ref.getFromAddress() + " in " + getFunctionContaining(ref.getFromAddress()));
            }
        }
        
        // 2. 也搜 "ClientExportKey" 
        addr = findString("ClientExportKey");
        if (addr != null) {
            println("ClientExportKey found at: " + addr);
            var refs = getReferencesTo(addr);
            for (var ref : refs) {
                println("  Ref by: " + ref.getFromAddress() + " in " + getFunctionContaining(ref.getFromAddress()));
            }
        }
        
        // 3. 搜索所有函数名包含 "Export" 的
        var fm = program.getFunctionManager();
        var funcs = fm.getFunctions(true);
        for (var func : funcs) {
            var name = func.getName();
            if (name.contains("Export") || name.contains("export")) {
                println("Export function: " + name + " at " + func.getEntryPoint());
            }
        }
        
        // 4. 搜索可能检查 NCRYPT_ALLOW_EXPORT_FLAG (1) 的 CMP/TEST 指令
        // NTE_PERM = 0x80090010
        // 搜索 "CMP reg, 1; JNZ fail" 或类似模式
        println("\nNote: Need manual analysis of ExportKey function to find the policy check.");
        println("Look for: CMP [export_policy_field], 0; JZ return_NTE_PERM");
    }
    
    String findString(String s) {
        var mem = getCurrentProgram().getMemory();
        var addr = mem.findBytes(mem.getMinAddress(), s.getBytes(), null, true, monitor);
        return addr != null ? addr.toString() : null;
    }
}
