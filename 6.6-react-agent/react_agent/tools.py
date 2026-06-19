from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    content: str


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated to {limit} chars]..."


class R2Tool:
    READ_ONLY_PREFIXES = {
        "i",
        "iI",
        "ij",
        "iij",
        "ij",
        "ie",
        "iej",
        "is",
        "isj",
        "ii",
        "iij",
        "afl",
        "aflj",
        "afi",
        "afij",
        "izz",
        "izzj",
        "iz",
        "izj",
        "pdf",
        "pdr",
        "pd",
        "px",
        "p8",
        "ps",
        "axt",
        "axtj",
        "axf",
        "axfj",
        "agC",
        "agf",
        "s",
        "CC",
    }
    FORBIDDEN_CHARS = {";", "|", ">", "<", "`", "\n", "\r"}

    def __init__(self, r2_path: str, target: Path, timeout: int = 30, max_chars: int = 12000):
        self.r2_path = r2_path
        self.target = target
        self.timeout = timeout
        self.max_chars = max_chars

    def check(self) -> dict[str, Any]:
        resolved = shutil.which(self.r2_path) if not Path(self.r2_path).is_absolute() else self.r2_path
        return {
            "tool": "radare2",
            "path": self.r2_path,
            "available": bool(resolved and Path(resolved).exists()),
        }

    def run(self, command: str) -> ToolResult:
        if not self.target.exists():
            return ToolResult(False, f"Target not found: {self.target}")
        try:
            self._validate_command(command)
        except ToolError as exc:
            return ToolResult(False, str(exc))

        args = [
            self.r2_path,
            "-q",
            "-2",
            "-A",
            "-c",
            command,
            "-c",
            "q",
            str(self.target),
        ]
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return ToolResult(False, f"radare2 executable not found: {self.r2_path}")
        except subprocess.TimeoutExpired:
            return ToolResult(False, f"radare2 timed out after {self.timeout}s: {command}")

        content = completed.stdout
        if completed.stderr:
            content += "\n[stderr]\n" + completed.stderr
        if completed.returncode != 0:
            return ToolResult(False, truncate(content or f"radare2 exit code {completed.returncode}", self.max_chars))
        return ToolResult(True, truncate(content or "(no output)", self.max_chars))

    def _validate_command(self, command: str) -> None:
        if not isinstance(command, str) or not command.strip():
            raise ToolError("r2 command must be a non-empty string.")
        if any(char in command for char in self.FORBIDDEN_CHARS) or "$(" in command or "!" in command:
            raise ToolError("r2 command rejected: command chaining, shell escapes, and redirection are disabled.")
        first = command.strip().split()[0]
        if first not in self.READ_ONLY_PREFIXES:
            raise ToolError(
                "r2 command rejected: only read-only analysis/print/info/xref commands are allowed."
            )


class GhidraTool:
    DANGER_TERMS = [
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "scanf",
        "__isoc99_scanf",
        "read",
        "recv",
        "memcpy",
        "system",
        "popen",
    ]

    def __init__(
        self,
        headless_path: str,
        target: Path,
        project_root: Path,
        java_home: str | None = None,
        timeout: int = 300,
        max_chars: int = 16000,
        max_functions: int = 200,
    ):
        self.headless_path = headless_path
        self.target = target
        self.project_root = project_root
        self.java_home = java_home
        self.timeout = timeout
        self.max_chars = max_chars
        self.max_functions = max_functions
        self.analysis: dict[str, Any] | None = None

    def check(self) -> dict[str, Any]:
        resolved = (
            shutil.which(self.headless_path)
            if not Path(self.headless_path).is_absolute()
            else self.headless_path
        )
        script = self.project_root / "ghidra_scripts" / "export_analysis.py"
        return {
            "tool": "Ghidra",
            "path": self.headless_path,
            "available": bool(resolved and Path(resolved).exists()),
            "java_home": self.java_home,
            "java_home_exists": bool(self.java_home and Path(self.java_home).exists()),
            "script": str(script),
            "script_exists": script.exists(),
        }

    def run(self, query: str, **kwargs: Any) -> ToolResult:
        if not self.target.exists():
            return ToolResult(False, f"Target not found: {self.target}")
        try:
            analysis = self._ensure_analysis()
        except ToolError as exc:
            return ToolResult(False, str(exc))

        query = (query or "summary").strip().lower()
        if query == "summary":
            return ToolResult(True, self._summary(analysis))
        if query == "list_functions":
            return ToolResult(True, self._list_functions(analysis))
        if query == "decompile":
            return ToolResult(True, self._decompile(analysis, kwargs.get("name"), kwargs.get("address")))
        if query == "search":
            return ToolResult(True, self._search(analysis, kwargs.get("pattern")))
        if query == "calls":
            return ToolResult(True, self._calls(analysis, kwargs.get("name"), kwargs.get("address")))
        return ToolResult(False, f"Unknown Ghidra query: {query}")

    def _ensure_analysis(self) -> dict[str, Any]:
        if self.analysis is not None:
            return self.analysis

        cache_dir = self.project_root / "cache" / "ghidra" / self._target_cache_key()
        output_dir = cache_dir / "output"
        analysis_file = output_dir / "analysis.json"
        if analysis_file.exists():
            self.analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
            return self.analysis

        script_dir = self.project_root / "ghidra_scripts"
        script_path = script_dir / "ExportAnalysis.java"
        if not script_path.exists():
            raise ToolError(f"Ghidra export script missing: {script_path}")

        output_dir.mkdir(parents=True, exist_ok=True)
        project_dir = cache_dir / "project"
        project_dir.mkdir(parents=True, exist_ok=True)
        args = [
            self.headless_path,
            str(project_dir),
            "react_static_project",
            "-import",
            str(self.target),
            "-overwrite",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "ExportAnalysis.java",
            str(output_dir),
            str(self.max_functions),
            "-deleteProject",
        ]
        try:
            env = os.environ.copy()
            if self.java_home:
                env["JAVA_HOME"] = self.java_home
                env["PATH"] = str(Path(self.java_home) / "bin") + os.pathsep + env.get("PATH", "")
            ghidra_user_home = Path(tempfile.gettempdir()) / "react_static_agent_ghidra_home"
            ghidra_user_home.mkdir(parents=True, exist_ok=True)
            user_home_arg = f"-Duser.home={ghidra_user_home}"
            existing_java_opts = env.get("JAVA_TOOL_OPTIONS", "").strip()
            env["JAVA_TOOL_OPTIONS"] = (
                user_home_arg if not existing_java_opts else user_home_arg + " " + existing_java_opts
            )
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            raise ToolError(f"Ghidra analyzeHeadless executable not found: {self.headless_path}")
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Ghidra analysis timed out after {self.timeout}s") from exc

        if completed.returncode != 0:
            detail = completed.stdout + "\n[stderr]\n" + completed.stderr
            raise ToolError(truncate("Ghidra analysis failed:\n" + detail, self.max_chars))
        if not analysis_file.exists():
            detail = completed.stdout + "\n[stderr]\n" + completed.stderr
            raise ToolError(truncate("Ghidra did not create analysis.json:\n" + detail, self.max_chars))

        self.analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
        return self.analysis

    def _target_cache_key(self) -> str:
        digest = sha256()
        digest.update(str(self.target).encode("utf-8"))
        try:
            digest.update(self.target.read_bytes())
        except OSError:
            pass
        return digest.hexdigest()[:16]

    def _summary(self, analysis: dict[str, Any]) -> str:
        functions = analysis.get("functions", [])
        imports = analysis.get("imports", [])
        strings = analysis.get("strings", [])
        payload = {
            "program": analysis.get("program", {}),
            "imports": imports[:80],
            "function_count": len(functions),
            "functions": [_function_header(item) for item in functions[:80]],
            "danger_hits": self._danger_hits(analysis)[:80],
            "interesting_strings": strings[:80],
        }
        return truncate(json.dumps(payload, indent=2, ensure_ascii=False), self.max_chars)

    def _list_functions(self, analysis: dict[str, Any]) -> str:
        payload = [_function_header(item) for item in analysis.get("functions", [])]
        return truncate(json.dumps(payload, indent=2, ensure_ascii=False), self.max_chars)

    def _decompile(self, analysis: dict[str, Any], name: Any, address: Any) -> str:
        function = self._find_function(analysis, name, address)
        if not function:
            return f"Function not found. name={name!r}, address={address!r}"
        return truncate(json.dumps(function, indent=2, ensure_ascii=False), self.max_chars)

    def _calls(self, analysis: dict[str, Any], name: Any, address: Any) -> str:
        function = self._find_function(analysis, name, address)
        if not function:
            return f"Function not found. name={name!r}, address={address!r}"
        payload = {
            "entry": function.get("entry"),
            "name": function.get("name"),
            "signature": function.get("signature"),
            "calls": function.get("calls", []),
        }
        return truncate(json.dumps(payload, indent=2, ensure_ascii=False), self.max_chars)

    def _search(self, analysis: dict[str, Any], pattern: Any) -> str:
        terms = [str(pattern).lower()] if pattern else self.DANGER_TERMS
        matches: list[dict[str, Any]] = []
        for function in analysis.get("functions", []):
            haystack = "\n".join(
                [
                    str(function.get("name", "")),
                    str(function.get("signature", "")),
                    str(function.get("decompiled", "")),
                    json.dumps(function.get("calls", []), ensure_ascii=False),
                ]
            ).lower()
            if any(term.lower() in haystack for term in terms):
                matches.append(function)
        for string_item in analysis.get("strings", []):
            value = str(string_item.get("value", "")).lower()
            if any(term.lower() in value for term in terms):
                matches.append({"string": string_item})
        return truncate(json.dumps(matches[:80], indent=2, ensure_ascii=False), self.max_chars)

    def _danger_hits(self, analysis: dict[str, Any]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for function in analysis.get("functions", []):
            called_names = " ".join(str(call.get("name", "")) for call in function.get("calls", []))
            text = " ".join(
                [
                    str(function.get("name", "")),
                    str(function.get("signature", "")),
                    called_names,
                    str(function.get("decompiled", "")),
                ]
            ).lower()
            terms = [term for term in self.DANGER_TERMS if term.lower() in text]
            if terms:
                hits.append(
                    {
                        "entry": function.get("entry"),
                        "name": function.get("name"),
                        "terms": sorted(set(terms)),
                    }
                )
        return hits

    def _find_function(self, analysis: dict[str, Any], name: Any, address: Any) -> dict[str, Any] | None:
        functions = analysis.get("functions", [])
        address_text = str(address).lower().strip() if address is not None else ""
        name_text = str(name).lower().strip() if name is not None else ""
        for function in functions:
            entry = str(function.get("entry", "")).lower()
            fname = str(function.get("name", "")).lower()
            if address_text and (entry == address_text or entry.endswith(address_text.replace("0x", ""))):
                return function
            if name_text and (fname == name_text or name_text in fname):
                return function
        return None


def _function_header(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "entry": function.get("entry"),
        "name": function.get("name"),
        "signature": function.get("signature"),
        "calls": function.get("calls", [])[:20],
    }
