from __future__ import annotations

import json
import re
from typing import Any


FENCED_BLOCK_RE = re.compile(r"```(?:json)?\s*\n?(.*?)```", re.IGNORECASE | re.DOTALL)
THINK_BLOCK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.IGNORECASE | re.DOTALL)
THINK_CLOSE_RE = re.compile(r"</think>", re.IGNORECASE)


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    seen: set[str] = set()

    for candidate in _candidate_segments(text):
        segment = candidate.strip()
        if not segment or segment in seen:
            continue
        seen.add(segment)

        try:
            parsed = json.loads(segment)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, dict):
                return parsed

        for start in _object_start_positions(segment):
            try:
                parsed, _end = decoder.raw_decode(segment[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed

    raise ValueError("no JSON object found in output")


def _candidate_segments(text: str) -> list[str]:
    cleaned = strip_model_reasoning(text)
    segments = [cleaned.strip()]
    if cleaned != text:
        segments.append(text.strip())
    segments.extend(match.group(1).strip() for match in FENCED_BLOCK_RE.finditer(cleaned))
    if cleaned != text:
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
