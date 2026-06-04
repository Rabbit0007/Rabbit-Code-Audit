from __future__ import annotations

from cairn.dispatcher.output_parser import extract_json_object, strip_model_reasoning


def test_extract_json_object_prefers_content_after_think_suffix():
    text = (
        'The prompt contains an example {"accepted": false, "reason": "example"}.\n'
        '</think>{"accepted": true, "data": {"description": "ok"}}'
    )

    assert extract_json_object(text) == {"accepted": True, "data": {"description": "ok"}}


def test_strip_model_reasoning_removes_closed_think_block():
    assert strip_model_reasoning("<think>hidden</think>{\"ok\": true}") == '{"ok": true}'


def test_strip_model_reasoning_uses_text_after_last_closing_marker():
    assert strip_model_reasoning("first </think> still thinking </think> pong") == "pong"
