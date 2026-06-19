import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.task.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class ExportAnalysis extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("export_analysis requires output_dir argument");
        }
        String outputDir = args[0];
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 200;

        Files.createDirectories(Paths.get(outputDir));

        Program program = getCurrentProgram();
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append("  \"program\": ");
        appendProgramInfo(sb, program);
        sb.append(",\n");

        sb.append("  \"imports\": ");
        appendImports(sb, program);
        sb.append(",\n");

        sb.append("  \"strings\": ");
        appendStrings(sb, program, 500);
        sb.append(",\n");

        sb.append("  \"functions\": ");
        appendFunctions(sb, program, maxFunctions);
        sb.append("\n}\n");

        File outputFile = Paths.get(outputDir, "analysis.json").toFile();
        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(outputFile), StandardCharsets.UTF_8)) {
            writer.write(sb.toString());
        }
        println("Wrote " + outputFile.getAbsolutePath());
    }

    private void appendProgramInfo(StringBuilder sb, Program program) {
        sb.append("{\n");
        sb.append("    \"name\": ").append(jsonEscape(program.getName())).append(",\n");
        sb.append("    \"executable_path\": ").append(jsonEscape(program.getExecutablePath())).append(",\n");
        sb.append("    \"language\": ").append(jsonEscape(program.getLanguage().getLanguageID().getIdAsString())).append(",\n");
        sb.append("    \"compiler\": ").append(jsonEscape(program.getCompilerSpec().getCompilerSpecID().getIdAsString())).append(",\n");
        sb.append("    \"image_base\": ").append(jsonEscape(program.getImageBase().toString())).append("\n");
        sb.append("  }");
    }

    private void appendStrings(StringBuilder sb, Program program, int maxItems) {
        sb.append("[\n");
        DataIterator stringIter = program.getListing().getDefinedData(true);
        int count = 0;
        boolean first = true;
        while (stringIter.hasNext() && count < maxItems) {
            Data data = stringIter.next();
            if (!data.hasStringValue()) continue;
            if (!first) sb.append(",\n");
            first = false;
            sb.append("    {");
            sb.append("\"address\": ").append(jsonEscape(data.getAddress().toString()));
            sb.append(", \"value\": ").append(jsonEscape(data.getDefaultValueRepresentation()));
            sb.append("}");
            count++;
        }
        sb.append("\n  ]");
    }

    private void appendImports(StringBuilder sb, Program program) {
        sb.append("[\n");
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator iterator = symbolTable.getExternalSymbols();
        boolean first = true;
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (!first) sb.append(",\n");
            first = false;
            sb.append("    {");
            sb.append("\"name\": ").append(jsonEscape(symbol.getName(true)));
            sb.append(", \"address\": ").append(jsonEscape(symbol.getAddress().toString()));
            sb.append("}");
        }
        sb.append("\n  ]");
    }

    private void appendCallList(StringBuilder sb, Program program, Function function) {
        sb.append("\"calls\": [\n");
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        boolean first = true;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Reference[] refs = instruction.getReferencesFrom();
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    if (!first) sb.append(",\n");
                    first = false;
                    Address target = ref.getToAddress();
                    Function targetFunction = functionManager.getFunctionAt(target);
                    sb.append("        {");
                    sb.append("\"from\": ").append(jsonEscape(instruction.getAddress().toString()));
                    sb.append(", \"to\": ").append(jsonEscape(target.toString()));
                    sb.append(", \"name\": ").append(jsonEscape(
                            targetFunction != null ? targetFunction.getName(true) : target.toString()));
                    sb.append("}");
                }
            }
        }
        sb.append("\n      ]");
    }

    private String decompileFunction(DecompInterface decompiler, Function function, ConsoleTaskMonitor monitor) {
        try {
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                return jsonEscape(result.getDecompiledFunction().getC());
            }
            if (result != null) {
                return jsonEscape("DECOMPILE_FAILED: " + result.getErrorMessage());
            }
        } catch (Exception e) {
            return jsonEscape("DECOMPILE_EXCEPTION: " + e.getMessage());
        }
        return jsonEscape("DECOMPILE_FAILED");
    }

    private void appendFunctions(StringBuilder sb, Program program, int maxFunctions) {
        sb.append("[\n");
        FunctionManager functionManager = program.getFunctionManager();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        int count = 0;
        boolean first = true;
        FunctionIterator iterator = functionManager.getFunctions(true);
        while (iterator.hasNext() && count < maxFunctions) {
            Function function = iterator.next();
            if (!first) sb.append(",\n");
            first = false;
            sb.append("    {\n");
            sb.append("      \"entry\": ").append(jsonEscape(function.getEntryPoint().toString())).append(",\n");
            sb.append("      \"name\": ").append(jsonEscape(function.getName(true))).append(",\n");
            sb.append("      \"signature\": ").append(jsonEscape(function.getSignature().toString())).append(",\n");
            sb.append("      \"is_thunk\": ").append(function.isThunk()).append(",\n");
            appendCallList(sb, program, function);
            sb.append(",\n");
            sb.append("      \"decompiled\": ").append(decompileFunction(decompiler, function, monitor)).append("\n");
            sb.append("    }");
            count++;
        }
        decompiler.dispose();
        sb.append("\n  ]");
    }

    private String jsonEscape(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder(s.length() + 4);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
