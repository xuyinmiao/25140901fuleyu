#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

import angr
import claripy


SYSTEM_PROMPT = """You are a ReAct-style reverse engineering agent.
Goal: use tool calls to solve the crackme input.
Constraints:
- Prefer paths that print "Success!".
- Avoid paths that print "Wrong password!" or "trapped".
- Keep each Thought short and actionable.
- Call exactly one tool per round.
"""

USER_GOAL = """Analyze ./crackme with angr tools and recover a concrete input.
The target is a small crackme compiled from crackme.c.
"""


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "inspect_target",
            "description": "Load the binary with angr and report architecture, entry point, useful symbols, and clue strings.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "controlled_explore",
            "description": "Run controlled symbolic execution from check_password and search for a state that prints Success while avoiding trap/wrong paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "input_len": {
                        "type": "integer",
                        "description": "Number of symbolic non-null input bytes before the terminator.",
                        "default": 9,
                    },
                    "max_steps": {
                        "type": "integer",
                        "description": "Maximum number of simulation steps.",
                        "default": 500,
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "solve_input",
            "description": "Solve concrete bytes from the success state found by controlled_explore.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_candidate",
            "description": "Run the real crackme binary with a candidate input and report stdout.",
            "parameters": {
                "type": "object",
                "properties": {
                    "candidate": {
                        "type": "string",
                        "description": "Concrete password candidate to send to stdin.",
                    }
                },
                "required": ["candidate"],
                "additionalProperties": False,
            },
        },
    },
]


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    tool_call_id: str | None = None


@dataclass
class RoundRecord:
    index: int
    thought: str
    action: str
    action_input: dict[str, Any]
    observation: dict[str, Any]


class AngrToolkit:
    def __init__(self, binary_path: Path) -> None:
        self.binary_path = binary_path
        self.project: angr.Project | None = None
        self.found_state: angr.SimState | None = None
        self.symbolic_bytes: list[Any] = []

    def _load_project(self) -> angr.Project:
        if not self.binary_path.exists():
            raise FileNotFoundError(f"binary not found: {self.binary_path}")
        if self.project is None:
            self.project = angr.Project(str(self.binary_path), auto_load_libs=False)
        return self.project

    def _find_symbol_addr(self, name: str) -> int | None:
        project = self._load_project()
        candidates = (name, f"_{name}")
        main_object = project.loader.main_object
        for symbol in main_object.symbols:
            if symbol.name in candidates and symbol.rebased_addr is not None:
                return int(symbol.rebased_addr)
            if symbol.name.lstrip("_") == name and symbol.rebased_addr is not None:
                return int(symbol.rebased_addr)
        for candidate in candidates:
            try:
                symbol = project.loader.find_symbol(candidate)
            except IndexError:
                symbol = None
            if symbol is not None and symbol.rebased_addr is not None:
                return int(symbol.rebased_addr)
        return None

    def _clue_strings(self) -> list[dict[str, Any]]:
        data = self.binary_path.read_bytes()
        clues: list[dict[str, Any]] = []
        keywords = ("Success", "Wrong", "trapped", "password", "%9s")
        for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
            text = match.group(0).decode("ascii", errors="replace")
            if any(keyword in text for keyword in keywords):
                clues.append({"offset": hex(match.start()), "text": text})
        return clues

    def inspect_target(self) -> dict[str, Any]:
        project = self._load_project()
        symbols = {}
        for name in ("main", "check_password", "gadget_trap", "strlen", "puts", "printf", "scanf"):
            addr = self._find_symbol_addr(name)
            if addr is not None:
                symbols[name] = hex(addr)

        return {
            "ok": True,
            "binary": str(self.binary_path),
            "arch": project.arch.name,
            "entry": hex(project.entry),
            "loader": type(project.loader.main_object).__name__,
            "symbols": symbols,
            "clue_strings": self._clue_strings(),
            "summary": (
                "Target loaded. check_password/gadget_trap symbols and Success/Wrong/trapped strings "
                "give the agent semantic anchors for controlled exploration."
            ),
        }

    def controlled_explore(self, input_len: int = 9, max_steps: int = 500) -> dict[str, Any]:
        if input_len < 4 or input_len > 32:
            return {"ok": False, "error": "input_len must be between 4 and 32"}

        project = self._load_project()
        check_addr = self._find_symbol_addr("check_password")
        if check_addr is None:
            return {"ok": False, "error": "check_password symbol not found"}

        buffer_addr = 0x50000000
        symbolic_bytes = [claripy.BVS(f"input_{i}", 8) for i in range(input_len)]
        symbolic_buffer = claripy.Concat(*symbolic_bytes, claripy.BVV(0, 8))

        state = project.factory.call_state(
            check_addr,
            buffer_addr,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.memory.store(buffer_addr, symbolic_buffer)

        for byte in symbolic_bytes:
            state.solver.add(byte >= 0x21)
            state.solver.add(byte <= 0x7E)

        def stdout_text(sim_state: angr.SimState) -> str:
            return sim_state.posix.dumps(1).decode("utf-8", errors="replace")

        def is_success(sim_state: angr.SimState) -> bool:
            return "Success!" in stdout_text(sim_state)

        def should_avoid(sim_state: angr.SimState) -> bool:
            output = stdout_text(sim_state)
            return "Wrong password!" in output or "trapped" in output

        simgr = project.factory.simulation_manager(state)
        steps = 0
        while (
            steps < max_steps
            and len(simgr.stashes.get("found", [])) == 0
            and len(simgr.stashes.get("active", [])) > 0
        ):
            simgr.explore(find=is_success, avoid=should_avoid, num_find=1, n=1)
            steps += 1

        stashes = {name: len(stash) for name, stash in simgr.stashes.items()}
        found_stash = simgr.stashes.get("found", [])
        if len(found_stash) == 0:
            return {
                "ok": False,
                "found": False,
                "steps": steps,
                "stashes": stashes,
                "summary": "No success state found within the step budget.",
            }

        self.found_state = found_stash[0]
        self.symbolic_bytes = symbolic_bytes
        return {
            "ok": True,
            "found": True,
            "steps": steps,
            "stashes": stashes,
            "found_addr": hex(self.found_state.addr),
            "stdout": stdout_text(self.found_state),
            "constraints": len(self.found_state.solver.constraints),
            "summary": "A state that emits Success! was found while trapped/wrong-output states were avoided.",
        }

    def solve_input(self) -> dict[str, Any]:
        if self.found_state is None or not self.symbolic_bytes:
            return {
                "ok": False,
                "error": "No success state available. Run controlled_explore first.",
            }

        model_bytes = self.found_state.solver.eval(
            claripy.Concat(*self.symbolic_bytes),
            cast_to=bytes,
        )

        unique_prefix = []
        byte_analysis = []
        for index, byte in enumerate(self.symbolic_bytes):
            values = self.found_state.solver.eval_upto(byte, 2, cast_to=int)
            unique = len(values) == 1
            chosen = model_bytes[index]
            byte_analysis.append(
                {
                    "index": index,
                    "unique": unique,
                    "chosen": chr(chosen) if 32 <= chosen <= 126 else hex(chosen),
                    "sample_values": [
                        chr(value) if 32 <= value <= 126 else hex(value)
                        for value in values
                    ],
                }
            )
            if unique:
                unique_prefix.append(chosen)
            else:
                break

        candidate_prefix = bytes(unique_prefix).decode("ascii", errors="replace")
        full_model = model_bytes.decode("ascii", errors="replace")

        return {
            "ok": True,
            "candidate_prefix": candidate_prefix,
            "one_full_model": full_model,
            "byte_analysis": byte_analysis,
            "summary": (
                f"Required constrained prefix is {candidate_prefix!r}. "
                "Later bytes are not semantically constrained by check_password."
            ),
        }

    def verify_candidate(self, candidate: str) -> dict[str, Any]:
        try:
            completed = subprocess.run(
                [str(self.binary_path)],
                input=f"{candidate}\n",
                text=True,
                capture_output=True,
                timeout=3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "candidate": candidate, "timeout": True}

        stdout = completed.stdout
        return {
            "ok": completed.returncode == 0 and "Success!" in stdout,
            "candidate": candidate,
            "returncode": completed.returncode,
            "stdout": stdout,
            "summary": "Candidate accepted by the real binary." if "Success!" in stdout else "Candidate was not accepted.",
        }


class ScriptedToolCallingClient:
    def __init__(self) -> None:
        self.round = 0

    def next_tool_call(self, _messages: list[dict[str, Any]]) -> tuple[str, ToolCall | None, dict[str, Any]]:
        self.round += 1
        if self.round == 1:
            payload = {
                "thought": "先检查目标的架构、符号和关键字符串，确定成功与陷阱语义锚点。",
                "action": "inspect_target",
                "action_input": {},
            }
        elif self.round == 2:
            payload = {
                "thought": "已看到 check_password 与 Success/trapped 字符串，从该函数入口做受控符号执行。",
                "action": "controlled_explore",
                "action_input": {"input_len": 9, "max_steps": 500},
            }
        elif self.round == 3:
            payload = {
                "thought": "成功状态已经出现，现在从该状态的约束里求解具体输入前缀。",
                "action": "solve_input",
                "action_input": {},
            }
        elif self.round == 4:
            payload = {
                "thought": "将求得的最小前缀喂给真实程序，确认它确实触发 Success 输出。",
                "action": "verify_candidate",
                "action_input": {"candidate": _latest_candidate(_messages) or "AZcE"},
            }
        else:
            return "任务已完成。", None, {"role": "assistant", "content": "DONE"}

        raw_content = json.dumps(payload, ensure_ascii=False)
        tool_call = parse_json_action(raw_content)
        return payload["thought"], tool_call, {"role": "assistant", "content": raw_content}


class OpenAIToolCallingClient:
    def __init__(self, model: str) -> None:
        from openai import OpenAI

        self.client = OpenAI()
        self.model = model

    def next_tool_call(self, messages: list[dict[str, Any]]) -> tuple[str, ToolCall | None, dict[str, Any]]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
        )
        message = response.choices[0].message
        raw: dict[str, Any] = {
            "role": "assistant",
            "content": message.content or "",
        }
        if message.tool_calls:
            raw["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
                for call in message.tool_calls
            ]
            call = message.tool_calls[0]
            args = json.loads(call.function.arguments or "{}")
            thought = (message.content or "").strip() or f"调用 {call.function.name} 获取下一步观察。"
            return thought, ToolCall(call.function.name, args, call.id), raw

        if message.content:
            tool_call = parse_json_action(message.content)
            if tool_call is not None:
                return tool_call.arguments.get("thought", ""), tool_call, raw

        return (message.content or "模型未给出工具调用。").strip(), None, raw


def _latest_candidate(messages: list[dict[str, Any]]) -> str | None:
    for message in reversed(messages):
        if message.get("role") != "tool":
            continue
        content = message.get("content")
        if not isinstance(content, str):
            continue
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            continue
        candidate = payload.get("candidate_prefix")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def parse_json_action(content: str) -> ToolCall | None:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return None
    action = payload.get("action")
    if not isinstance(action, str):
        return None
    action_input = payload.get("action_input", {})
    if not isinstance(action_input, dict):
        action_input = {}
    return ToolCall(action, action_input)


class AgentRunner:
    def __init__(self, toolkit: AngrToolkit, llm_client: Any, log_path: Path) -> None:
        self.toolkit = toolkit
        self.llm_client = llm_client
        self.log_path = log_path
        self.records: list[RoundRecord] = []
        self.messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_GOAL},
        ]

    def dispatch(self, tool_call: ToolCall) -> dict[str, Any]:
        tool_map = {
            "inspect_target": self.toolkit.inspect_target,
            "controlled_explore": self.toolkit.controlled_explore,
            "solve_input": self.toolkit.solve_input,
            "verify_candidate": self.toolkit.verify_candidate,
        }
        tool = tool_map.get(tool_call.name)
        if tool is None:
            return {"ok": False, "error": f"Unknown tool: {tool_call.name}"}
        try:
            return tool(**tool_call.arguments)
        except Exception as exc:  # Keep the observation structured for the next ReAct round.
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def run(self, max_rounds: int) -> list[RoundRecord]:
        for index in range(1, max_rounds + 1):
            thought, tool_call, raw_assistant_message = self.llm_client.next_tool_call(self.messages)
            self.messages.append(raw_assistant_message)
            if tool_call is None:
                break

            observation = self.dispatch(tool_call)
            self.records.append(
                RoundRecord(
                    index=index,
                    thought=thought,
                    action=tool_call.name,
                    action_input=tool_call.arguments,
                    observation=observation,
                )
            )

            if tool_call.tool_call_id is not None:
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.tool_call_id,
                        "name": tool_call.name,
                        "content": json.dumps(observation, ensure_ascii=False),
                    }
                )
            else:
                self.messages.append(
                    {
                        "role": "tool",
                        "name": tool_call.name,
                        "content": json.dumps(observation, ensure_ascii=False),
                    }
                )

            if tool_call.name == "verify_candidate" and observation.get("ok") is True:
                break

        self.write_log()
        return self.records

    def write_log(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# ReAct Run Log",
            "",
            f"Binary: `{self.toolkit.binary_path}`",
            "",
        ]
        for record in self.records:
            lines.extend(
                [
                    f"## Round {record.index}",
                    "",
                    f"Thought: {record.thought}",
                    "",
                    f"Action: `{record.action}({json.dumps(record.action_input, ensure_ascii=False)})`",
                    "",
                    "Observation:",
                    "",
                    "```json",
                    json.dumps(record.observation, ensure_ascii=False, indent=2),
                    "```",
                    "",
                ]
            )
        self.log_path.write_text("\n".join(lines), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ReAct agent lab: LLM tool loop + angr crackme solving")
    parser.add_argument("--binary", default="./crackme", help="Path to the compiled crackme binary")
    parser.add_argument("--llm", choices=("mock", "openai"), default="mock", help="LLM backend")
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", ""), help="OpenAI model name")
    parser.add_argument("--max-rounds", type=int, default=4, help="Maximum ReAct rounds")
    parser.add_argument("--log", default="logs/react_run.md", help="Path for Thought/Action/Observation log")
    return parser


def main(argv: list[str]) -> int:
    args = build_arg_parser().parse_args(argv)
    binary_path = Path(args.binary).resolve()
    toolkit = AngrToolkit(binary_path)

    if args.llm == "openai":
        if not os.environ.get("OPENAI_API_KEY"):
            print("OPENAI_API_KEY is required for --llm openai", file=sys.stderr)
            return 2
        if not args.model:
            print("Set --model or OPENAI_MODEL for --llm openai", file=sys.stderr)
            return 2
        llm_client = OpenAIToolCallingClient(args.model)
    else:
        llm_client = ScriptedToolCallingClient()

    runner = AgentRunner(toolkit=toolkit, llm_client=llm_client, log_path=Path(args.log))
    records = runner.run(args.max_rounds)

    for record in records:
        print(f"Round {record.index}")
        print(f"Thought: {record.thought}")
        print(f"Action: {record.action}({json.dumps(record.action_input, ensure_ascii=False)})")
        print(f"Observation: {json.dumps(record.observation, ensure_ascii=False)}")
        print()
    print(f"Saved log to {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
