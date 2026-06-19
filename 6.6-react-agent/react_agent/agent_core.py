from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any

from .config import AgentConfig
from .llm import OpenAIChatClient
from .logging_utils import RunLog
from .parser import FinalAnswer, ParseError, ToolCall, parse_react_response
from .tools import GhidraTool, R2Tool, ToolResult


class ReActStaticAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = RunLog(config.log_path)
        self.r2 = R2Tool(
            config.r2_path,
            config.target,
            timeout=config.r2_timeout,
            max_chars=config.max_observation_chars,
        )
        self.ghidra = GhidraTool(
            config.ghidra_headless,
            config.target,
            config.project_root,
            java_home=config.java_home,
            timeout=config.ghidra_timeout,
            max_chars=config.max_observation_chars,
            max_functions=config.ghidra_max_functions,
        )
        self.llm = OpenAIChatClient(
            model=config.model,
            api_key_env=config.api_key_env,
            base_url=config.base_url,
        )

    def run(self) -> FinalAnswer:
        self.config.ensure_output_dirs()
        self.log.reset()
        system_prompt = self.config.read_prompt()
        initial_task = self._initial_task()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_task},
        ]
        used_tools: set[str] = set()

        self.log.write(
            "Run Metadata",
            "\n".join(
                [
                    f"date: {date.today().isoformat()}",
                    f"model: {self.config.model}",
                    f"target: {self.config.target}",
                    f"radare2: {self.config.r2_path}",
                    f"ghidra_headless: {self.config.ghidra_headless}",
                    f"java_home: {self.config.java_home or '(not set)'}",
                ]
            ),
        )
        self.log.write("Initial Task", initial_task)

        for round_index in range(1, self.config.max_rounds + 1):
            assistant_text = self.llm.complete(messages)
            self.log.write(f"Round {round_index:02d} Assistant", assistant_text)

            try:
                parsed = parse_react_response(assistant_text)
            except ParseError as exc:
                feedback = self._parser_feedback(exc)
                self.log.write(f"Round {round_index:02d} Parser Feedback", feedback)
                messages.extend(
                    [
                        {"role": "assistant", "content": assistant_text},
                        {"role": "user", "content": feedback},
                    ]
                )
                continue

            if isinstance(parsed, FinalAnswer):
                if not {"r2", "ghidra"}.issubset(used_tools):
                    feedback = (
                        "Final rejected: before Final you must call both tools at least once. "
                        f"Tools used so far: {sorted(used_tools)}. Continue with an Action."
                    )
                    self.log.write(f"Round {round_index:02d} Final Rejected", feedback)
                    messages.extend(
                        [
                            {"role": "assistant", "content": assistant_text},
                            {"role": "user", "content": feedback},
                        ]
                    )
                    continue
                self._write_final(parsed)
                return parsed

            result = self._dispatch(parsed)
            if result.ok:
                used_tools.add(_canonical_tool(parsed.tool))
            observation = self._format_observation(parsed, result)
            self.log.write(f"Round {round_index:02d} Observation", observation)
            messages.extend(
                [
                    {"role": "assistant", "content": assistant_text},
                    {"role": "user", "content": observation + "\nContinue."},
                ]
            )

        raise RuntimeError(f"Agent stopped after max rounds without Final: {self.config.max_rounds}")

    def _dispatch(self, call: ToolCall) -> ToolResult:
        tool = _canonical_tool(call.tool)
        args = call.args
        if tool == "r2":
            command = args.get("command")
            if not isinstance(command, str):
                return ToolResult(False, "r2 action requires args.command string.")
            return self.r2.run(command)
        if tool == "ghidra":
            query = args.get("query", "summary")
            return self.ghidra.run(
                str(query),
                name=args.get("name") or args.get("function"),
                address=args.get("address"),
                pattern=args.get("pattern"),
            )
        return ToolResult(False, f"Unknown tool: {call.tool}. Use 'r2' or 'ghidra'.")

    def _initial_task(self) -> str:
        return "\n".join(
            [
                "Analyze the binary target using only tool observations.",
                f"Target path: {self.config.target}",
                "You must call r2 and Ghidra at least once before Final.",
                "Write Final only when the vulnerability conclusion is grounded in the observations.",
            ]
        )

    def _format_observation(self, call: ToolCall, result: ToolResult) -> str:
        status = "ok" if result.ok else "error"
        return (
            f"Observation from {_canonical_tool(call.tool)} ({status})\n"
            f"Action args: {json.dumps(call.args, ensure_ascii=False)}\n"
            f"{result.content}"
        )

    def _parser_feedback(self, exc: ParseError) -> str:
        return (
            "Your previous response could not be parsed: "
            f"{exc}\n"
            "Use exactly one of these formats:\n"
            'Thought: ...\nAction:\n{"tool":"r2","args":{"command":"iI"}}\n'
            'Thought: ...\nFinal:\n{"vuln_type":"...","location":"...","cause":"..."}'
        )

    def _write_final(self, final: FinalAnswer) -> None:
        payload = final.to_dict()
        self.config.output_json.parent.mkdir(parents=True, exist_ok=True)
        self.config.output_json.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self.log.write("Final Answer", json.dumps(payload, indent=2, ensure_ascii=False))


def environment_status(config: AgentConfig) -> dict[str, Any]:
    r2 = R2Tool(config.r2_path, config.target, config.r2_timeout, config.max_observation_chars)
    ghidra = GhidraTool(
        config.ghidra_headless,
        config.target,
        config.project_root,
        java_home=config.java_home,
        timeout=config.ghidra_timeout,
        max_chars=config.max_observation_chars,
        max_functions=config.ghidra_max_functions,
    )
    return {
        "project_root": str(config.project_root),
        "target": str(config.target),
        "target_exists": config.target.exists(),
        "prompt": str(config.prompt_path),
        "prompt_exists": config.prompt_path.exists(),
        "log_path": str(config.log_path),
        "output_json": str(config.output_json),
        "model": config.model,
        "r2": r2.check(),
        "ghidra": ghidra.check(),
    }


def _canonical_tool(name: str) -> str:
    lowered = name.strip().lower()
    if lowered in {"r2", "radare2"}:
        return "r2"
    if lowered in {"ghidra", "ghidra_headless"}:
        return "ghidra"
    return lowered
