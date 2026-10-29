// SPDX-License-Identifier: AGPL-3.0
// Copyright (c) 2026 Arafat Zahan (@kuasha420)
// Corporate Stewardship & Infrastructure: Purrfect Software Limited (PSL)
// Governed by: ICARO-42/b Ordinance (Company-Supported Personal IP Framework)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class ExportGhidraData extends GhidraScript {

    @Override
    public void run() throws Exception {
        String name = currentProgram.getName();
        long imageBase = currentProgram.getImageBase().getOffset();
        println("[ExportGhidraData] Processing: " + name + " (Image Base: 0x" + Long.toHexString(imageBase) + ")");

        String envDir = System.getenv("IMMORTAL_DIRTYROOM");
        File outDir;
        if (envDir != null && !envDir.trim().isEmpty()) {
            outDir = new File(envDir, "symbols");
        } else {
            outDir = new File("/mnt/fast_data/re_dirtyroom/paladins_8.1.5839.0/symbols");
        }
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        File funcsFile = new File(outDir, "functions_" + name + ".jsonl");
        File symsFile = new File(outDir, "symbols_" + name + ".jsonl");

        // 1. Export Functions
        println("[ExportGhidraData] Exporting functions to " + funcsFile.getAbsolutePath());
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(funcsFile))) {
            while (funcs.hasNext()) {
                Function f = funcs.next();
                long entry = f.getEntryPoint().getOffset();
                String fname = f.getName().replace("\"", "\\\"");
                String sig = f.getSignature().toString().replace("\"", "\\\"");
                long size = f.getBody().getNumAddresses();
                boolean isThunk = f.isThunk();

                writer.write("{\"program\":\"" + name + "\",\"address\":" + entry +
                             ",\"name\":\"" + fname + "\",\"signature\":\"" + sig +
                             "\",\"size\":" + size + ",\"is_thunk\":" + isThunk + "}\n");
                funcCount++;
            }
        }
        println("[ExportGhidraData] Successfully exported " + funcCount + " functions.");

        // 2. Export All Symbols
        println("[ExportGhidraData] Exporting symbols to " + symsFile.getAbsolutePath());
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        int symCount = 0;
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(symsFile))) {
            while (symbols.hasNext()) {
                Symbol s = symbols.next();
                long addr = s.getAddress().getOffset();
                String sname = s.getName().replace("\"", "\\\"");
                String stype = s.getSymbolType().toString();

                writer.write("{\"program\":\"" + name + "\",\"address\":" + addr +
                             ",\"name\":\"" + sname + "\",\"type\":\"" + stype + "\"}\n");
                symCount++;
            }
        }
        println("[ExportGhidraData] Successfully exported " + symCount + " symbols.");
    }
}
