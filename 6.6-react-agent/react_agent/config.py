from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil


DEFAULT_MODEL = "gpt-4.1-mini"


def resolve_executable(value: str | None, fallback_name: str) -> str:
    if value:
        return value
    found = shutil.which(fallback_name)
    return found or fallback_name


def resolve_ghidra_headless(project_root: Path, value: str | None) -> str:
    if value:
        return value
    local = project_root / "tools" / "ghidra_12.1.2_PUBLIC" / "support" / "analyzeHeadless"
    if local.exists():
        return str(local)
    return resolve_executable(None, "analyzeHeadless")


def resolve_java_home(value: str | None) -> str | None:
    if value:
        return value
    homebrew_jdk = Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
    if homebrew_jdk.exists():
        return str(homebrew_jdk)
    return None


@dataclass(frozen=True)
class AgentConfig:
    project_root: Path
    target: Path
    model: str
    r2_path: str
    ghidra_headless: str
    java_home: str | None
    log_path: Path
    output_json: Path
    prompt_path: Path
    max_rounds: int
    api_key_env: str
    base_url: str | None
    r2_timeout: int
    ghidra_timeout: int
    ghidra_max_functions: int
    max_observation_chars: int

    @classmethod
    def from_args(cls, args) -> "AgentConfig":
        project_root = Path(args.project_root).expanduser().resolve()
        return cls(
            project_root=project_root,
            target=(project_root / args.target).resolve()
            if not Path(args.target).is_absolute()
            else Path(args.target).expanduser().resolve(),
            model=args.model or os.getenv("OPENAI_MODEL") or DEFAULT_MODEL,
            r2_path=resolve_executable(args.r2_path or os.getenv("R2_PATH"), "r2"),
            ghidra_headless=resolve_ghidra_headless(
                project_root,
                args.ghidra_headless or os.getenv("GHIDRA_HEADLESS"),
            ),
            java_home=resolve_java_home(args.java_home or os.getenv("JAVA_HOME")),
            log_path=(project_root / args.log_path).resolve()
            if not Path(args.log_path).is_absolute()
            else Path(args.log_path).expanduser().resolve(),
            output_json=(project_root / args.output_json).resolve()
            if not Path(args.output_json).is_absolute()
            else Path(args.output_json).expanduser().resolve(),
            prompt_path=(project_root / args.prompt_path).resolve()
            if not Path(args.prompt_path).is_absolute()
            else Path(args.prompt_path).expanduser().resolve(),
            max_rounds=args.max_rounds,
            api_key_env=args.api_key_env,
            base_url=args.base_url or os.getenv("OPENAI_BASE_URL"),
            r2_timeout=args.r2_timeout,
            ghidra_timeout=args.ghidra_timeout,
            ghidra_max_functions=args.ghidra_max_functions,
            max_observation_chars=args.max_observation_chars,
        )

    def ensure_output_dirs(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_json.parent.mkdir(parents=True, exist_ok=True)
        (self.project_root / "cache" / "ghidra").mkdir(parents=True, exist_ok=True)

    def read_prompt(self) -> str:
        return self.prompt_path.read_text(encoding="utf-8")
