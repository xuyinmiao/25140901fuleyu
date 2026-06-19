from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .agent_core import ReActStaticAgent, environment_status
from .config import AgentConfig, DEFAULT_MODEL
from .env_file import load_env_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ReAct Agent for static binary vulnerability analysis with radare2 and Ghidra."
    )
    parser.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--target", default="targets/challenge")
    parser.add_argument("--model", default=None, help=f"LLM model. Default: OPENAI_MODEL or {DEFAULT_MODEL}")
    parser.add_argument("--base-url", default=None, help="Optional OpenAI-compatible base URL.")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--r2-path", default=None, help="radare2 executable path. Default: R2_PATH or r2")
    parser.add_argument(
        "--ghidra-headless",
        default=None,
        help="Ghidra analyzeHeadless path. Default: GHIDRA_HEADLESS or analyzeHeadless",
    )
    parser.add_argument(
        "--java-home",
        default=None,
        help="Optional Java 21 home used when launching Ghidra. Default: JAVA_HOME.",
    )
    parser.add_argument("--log-path", default="logs/run.txt")
    parser.add_argument("--output-json", default="output/vuln.json")
    parser.add_argument("--prompt-path", default="prompts/system_prompt.txt")
    parser.add_argument("--max-rounds", type=int, default=12)
    parser.add_argument("--r2-timeout", type=int, default=30)
    parser.add_argument("--ghidra-timeout", type=int, default=300)
    parser.add_argument("--ghidra-max-functions", type=int, default=200)
    parser.add_argument("--max-observation-chars", type=int, default=16000)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only print configuration/tool status. Does not call the LLM or analysis tools.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = Path(args.project_root).expanduser().resolve()
    load_env_file(project_root / ".env")
    config = AgentConfig.from_args(args)
    config.ensure_output_dirs()

    if args.check:
        print(json.dumps(environment_status(config), indent=2, ensure_ascii=False))
        return 0

    agent = ReActStaticAgent(config)
    final = agent.run()
    print(json.dumps(final.to_dict(), indent=2, ensure_ascii=False))
    print(f"Wrote log: {config.log_path}")
    print(f"Wrote result: {config.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
