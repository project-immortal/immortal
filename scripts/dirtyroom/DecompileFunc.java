// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileFunc extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            println("Error: No function address or symbol provided to decompile.");
            return;
        }

        String target = args[0];
        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = null;

        if (target.startsWith("0x") || target.startsWith("0X")) {
            long addrVal = Long.parseUnsignedLong(target.substring(2), 16);
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrVal);
            func = fm.getFunctionContaining(addr);
        } else {
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(target);
            while (symbols.hasNext()) {
                Symbol s = symbols.next();
                Function f = fm.getFunctionAt(s.getAddress());
                if (f != null) {
                    func = f;
                    break;
                }
            }
        }

        if (func == null) {
            println("Error: Function not found for target: " + target);
            return;
        }

        println("=== Decompilation: " + func.getName() + " at " + func.getEntryPoint() + " ===");
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (results.decompileCompleted()) {
            println(results.getDecompiledFunction().getC());
        } else {
            println("Error: Decompilation failed: " + results.getErrorMessage());
        }
    }
}
