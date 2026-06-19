from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]


@dataclass(frozen=True)
class FinalAnswer:
    vuln_type: str
    location: str
    cause: str

    def to_dict(self) -> dict[str, str]:
        return {
            "vuln_type": self.vuln_type,
            "location": self.location,
            "cause": self.cause,
        }


def parse_react_response(text: str) -> ToolCall | FinalAnswer:
    final_json = _json_after_label(text, "Final")
    if final_json is not None:
        return _parse_final(final_json)

    action_json = _json_after_label(text, "Action")
    if action_json is None:
        action_json = _first_json_object(text)
    if action_json is None:
        raise ParseError("No Action or Final JSON object found.")
    return _parse_action(action_json)


def _parse_action(data: dict[str, Any]) -> ToolCall:
    action = data.get("action") or data.get("tool")
    if not isinstance(action, str) or not action.strip():
        raise ParseError("Action JSON must include string field 'action' or 'tool'.")

    if action.lower() == "final":
        payload = data.get("args") or data.get("final") or data
        if not isinstance(payload, dict):
            raise ParseError("Final payload must be a JSON object.")
        return _parse_final(payload)

    args = data.get("args", {})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ParseError("Action field 'args' must be a JSON object.")
    return ToolCall(tool=action.strip().lower(), args=args)


def _parse_final(data: dict[str, Any]) -> FinalAnswer:
    missing = [key for key in ("vuln_type", "location", "cause") if key not in data]
    if missing:
        raise ParseError("Final JSON missing fields: " + ", ".join(missing))
    values = {key: str(data[key]).strip() for key in ("vuln_type", "location", "cause")}
    if not all(values.values()):
        raise ParseError("Final JSON fields must be non-empty strings.")
    return FinalAnswer(**values)


def _json_after_label(text: str, label: str) -> dict[str, Any] | None:
    match = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*", text)
    if not match:
        return None
    return _first_json_object(text[match.end() :])


def _first_json_object(text: str) -> dict[str, Any] | None:
    cleaned = _strip_code_fences(text)
    start = cleaned.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                raw = cleaned[start : index + 1]
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ParseError(f"Invalid JSON object: {exc}") from exc
                if not isinstance(parsed, dict):
                    raise ParseError("Parsed JSON value is not an object.")
                return parsed
    raise ParseError("Unclosed JSON object.")


def _strip_code_fences(text: str) -> str:
    return re.sub(r"```(?:json)?|```", "", text, flags=re.IGNORECASE)
