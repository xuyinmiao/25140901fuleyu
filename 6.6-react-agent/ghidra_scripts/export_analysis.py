# Ghidra Jython script. Run through analyzeHeadless with:
# -postScript export_analysis.py <output_dir> <max_functions>

from __future__ import print_function

from ghidra.app.decompiler import DecompInterface
from ghidra.program.util import DefinedDataIterator
from ghidra.util.task import ConsoleTaskMonitor

import json
import os
import codecs


def safe_text(value):
    try:
        return unicode(value)
    except NameError:
        return str(value)
    except Exception:
        return str(value)


def get_program_info(program):
    lang = program.getLanguage()
    compiler = program.getCompilerSpec()
    return {
        "name": safe_text(program.getName()),
        "executable_path": safe_text(program.getExecutablePath()),
        "language": safe_text(lang.getLanguageID()),
        "compiler": safe_text(compiler.getCompilerSpecID()),
        "image_base": safe_text(program.getImageBase()),
    }


def export_strings(program, max_items):
    values = []
    iterator = DefinedDataIterator.definedStrings(program)
    count = 0
    while iterator.hasNext() and count < max_items:
        data = iterator.next()
        values.append(
            {
                "address": safe_text(data.getAddress()),
                "value": safe_text(data.getValue()),
            }
        )
        count += 1
    return values


def export_imports(program):
    symbols = []
    symbol_table = program.getSymbolTable()
    iterator = symbol_table.getExternalSymbols()
    while iterator.hasNext():
        symbol = iterator.next()
        symbols.append(
            {
                "name": safe_text(symbol.getName(True)),
                "address": safe_text(symbol.getAddress()),
            }
        )
    return symbols


def collect_calls(program, function):
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    calls = []
    instructions = listing.getInstructions(function.getBody(), True)
    while instructions.hasNext():
        instruction = instructions.next()
        refs = instruction.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                target_function = function_manager.getFunctionAt(target)
                calls.append(
                    {
                        "from": safe_text(instruction.getAddress()),
                        "to": safe_text(target),
                        "name": safe_text(target_function.getName(True))
                        if target_function
                        else safe_text(target),
                    }
                )
    return calls


def decompile_function(decompiler, function, monitor):
    try:
        result = decompiler.decompileFunction(function, 30, monitor)
        if result and result.decompileCompleted() and result.getDecompiledFunction():
            return safe_text(result.getDecompiledFunction().getC())
        if result:
            return "DECOMPILE_FAILED: " + safe_text(result.getErrorMessage())
    except Exception as exc:
        return "DECOMPILE_EXCEPTION: " + safe_text(exc)
    return "DECOMPILE_FAILED"


def export_functions(program, max_functions):
    function_manager = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    functions = []
    count = 0
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext() and count < max_functions:
        function = iterator.next()
        functions.append(
            {
                "entry": safe_text(function.getEntryPoint()),
                "name": safe_text(function.getName(True)),
                "signature": safe_text(function.getSignature()),
                "is_thunk": bool(function.isThunk()),
                "calls": collect_calls(program, function),
                "decompiled": decompile_function(decompiler, function, monitor),
            }
        )
        count += 1
    decompiler.dispose()
    return functions


def main():
    args = getScriptArgs()
    if len(args) < 1:
        raise Exception("export_analysis.py requires output_dir argument")
    output_dir = args[0]
    max_functions = int(args[1]) if len(args) > 1 else 200
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    program = currentProgram
    payload = {
        "program": get_program_info(program),
        "imports": export_imports(program),
        "strings": export_strings(program, 500),
        "functions": export_functions(program, max_functions),
    }

    output_path = os.path.join(output_dir, "analysis.json")
    with codecs.open(output_path, "w", "utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    print("Wrote " + output_path)


main()
