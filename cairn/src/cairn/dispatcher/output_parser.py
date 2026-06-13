from __future__ import annotations

import ast
import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)
THINK_BLOCK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)
THINK_CLOSE_RE = re.compile(r"</think>", re.IGNORECASE)
TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")
BARE_KEY_RE = re.compile(r'([{\[,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:')
PY_CONSTANT_RE = re.compile(r"\b(True|False|None)\b")
STRONG_PAYLOAD_KEYS = {
    "accepted",
    "data",
    "complete",
    "intents",
    "intent",
    "fact",
    "finding",
    "findings",
    "review",
    "reviews",
    "packet_templates",
    "reproduction_poc",
    "evidence_chain",
    "report_sections",
    "tool_findings",
    "audit_candidates",
    "candidate_conclusions",
    "business_nodes",
    "business_edges",
    "business_node_conclusions",
}


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    seen: set[str] = set()
    fallback: dict[str, Any] | None = None

    for candidate in _candidate_segments(text):
        for segment in _repaired_segments(candidate):
            segment = segment.strip()
            if not segment or segment in seen:
                continue
            seen.add(segment)

            parsed = _loads_dict(segment)
            if isinstance(parsed, dict):
                if _is_strong_payload(parsed):
                    return parsed
                fallback = fallback or parsed

            for start in _object_start_positions(segment):
                parsed = _raw_decode_dict(decoder, segment[start:])
                if isinstance(parsed, dict):
                    if _is_strong_payload(parsed):
                        return parsed
                    fallback = fallback or parsed

    if fallback is not None:
        return fallback
    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    cleaned = strip_model_reasoning(text)
    segments = _jsonl_message_texts(cleaned)
    segments.append(cleaned.strip())
    segments.extend(match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(cleaned))
    if cleaned != text:
        segments.extend(_jsonl_message_texts(text))
        segments.append(text.strip())
        segments.extend(match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(text))
    return segments


def _object_start_positions(text: str) -> list[int]:
    return [index for index, char in enumerate(text) if char == "{"]


def strip_model_reasoning(text: str) -> str:
    stripped = text.strip()
    matches = list(THINK_CLOSE_RE.finditer(stripped))
    if matches:
        return stripped[matches[-1].end():].strip()
    return THINK_BLOCK_RE.sub("", stripped).strip()


def _jsonl_message_texts(text: str) -> list[str]:
    """Extract assistant text from JSONL event streams.

    Pi/Codex-style tools often print event JSON lines around the actual model
    answer. Task code normally asks the driver to extract the assistant message,
    but this fallback keeps parsing robust when raw event streams reach the
    parser in tests or after adapter changes.
    """
    messages: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        event_type = event.get("type")
        if event_type in {"turn_end", "message_start"}:
            message = event.get("message")
            if isinstance(message, dict) and message.get("role") == "assistant":
                message_text = _message_content_text(message)
                if message_text:
                    messages.append(message_text)
        elif event_type == "agent_end":
            event_messages = event.get("messages")
            if not isinstance(event_messages, list):
                continue
            for message in reversed(event_messages):
                if not isinstance(message, dict) or message.get("role") != "assistant":
                    continue
                message_text = _message_content_text(message)
                if message_text:
                    messages.append(message_text)
                break
    return messages


def _message_content_text(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
    return "\n".join(parts).strip()


def _repaired_segments(text: str) -> list[str]:
    segment = text.strip()
    if not segment:
        return []
    variants = [segment]
    normalized_quotes = (
        segment.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )
    variants.append(normalized_quotes)
    for item in list(variants):
        variants.append(TRAILING_COMMA_RE.sub(r"\1", item))
    for item in list(variants):
        variants.append(_jsonish_python_constants(item))
    for item in list(variants):
        variants.append(BARE_KEY_RE.sub(r'\1"\2":', item))

    repaired: list[str] = []
    seen: set[str] = set()
    for item in variants:
        item = item.strip()
        if item and item not in seen:
            repaired.append(item)
            seen.add(item)
    return repaired


def _jsonish_python_constants(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(1)
        return {"True": "true", "False": "false", "None": "null"}[value]

    return PY_CONSTANT_RE.sub(replace, text)


def _loads_dict(text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = _literal_eval_dict(text)
    return parsed if isinstance(parsed, dict) else None


def _raw_decode_dict(decoder: json.JSONDecoder, text: str) -> dict[str, Any] | None:
    try:
        parsed, _end = decoder.raw_decode(text)
    except json.JSONDecodeError:
        parsed = _literal_eval_dict(text)
    return parsed if isinstance(parsed, dict) else None


def _literal_eval_dict(text: str) -> dict[str, Any] | None:
    try:
        parsed = ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_strong_payload(value: dict[str, Any]) -> bool:
    return bool(STRONG_PAYLOAD_KEYS & set(value))
