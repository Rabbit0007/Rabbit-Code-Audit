from __future__ import annotations

from cairn.dispatcher.contracts import salvage_unproven_explore_findings, validate_explore_payload
from cairn.dispatcher.output_parser import extract_json_object, strip_model_reasoning
from cairn.dispatcher.runtime.process import TRUNCATION_MARKER, _BoundedTextBuffer


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


def test_extract_json_object_from_jsonl_assistant_event():
    text = "\n".join(
        [
            '{"type":"session","id":"s1"}',
            '{"type":"turn_end","message":{"role":"assistant","content":[{"type":"text","text":"```json\\n{\\"accepted\\": true, \\"data\\": {\\"description\\": \\"ok\\"}}\\n```"}]}}',
        ]
    )

    assert extract_json_object(text) == {"accepted": True, "data": {"description": "ok"}}


def test_extract_json_object_repairs_common_formatting_noise():
    text = """
    Here is the result:
    ```json
    {
      accepted: True,
      data: {
        description: "ok",
      },
    }
    ```
    """

    assert extract_json_object(text) == {"accepted": True, "data": {"description": "ok"}}


def test_bounded_process_output_retains_tail_for_final_json():
    buffer = _BoundedTextBuffer(limit=80)
    buffer.append("reasoning " * 30)
    buffer.append('{"accepted": true, "data": {"description": "ok"}}')

    rendered = buffer.render()
    assert rendered.startswith(TRUNCATION_MARKER)
    assert extract_json_object(rendered) == {"accepted": True, "data": {"description": "ok"}}


def test_unproven_high_finding_is_salvaged_as_candidate():
    payload = {
        "accepted": True,
        "data": {
            "description": "发现可疑 SQL 拼接",
            "findings": [
                {
                    "title": "SQL 注入",
                    "category": "injection",
                    "severity": "high",
                    "description": "参数直接拼接",
                    "file_path": "index.php",
                    "line_start": 10,
                    "entry_point": "/index.php",
                    "impact": "读取数据库",
                    "evidence": "index.php:10",
                }
            ],
        },
    }

    salvaged = salvage_unproven_explore_findings(payload)
    kind, data = validate_explore_payload(salvaged)

    assert kind == "fact"
    assert data["findings"] == []
    assert data["audit_candidates"][0]["candidate_type"] == "finding_needs_proof"
