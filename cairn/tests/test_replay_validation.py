"""Prove the server-side replay verifier against a labeled lab target.

The lab target exposes a vulnerable endpoint and a safe twin for each bug class.
For every oracle we assert two things that matter for a verifier:

  * it returns ``confirmed`` on the vulnerable endpoint (no false negative), and
  * it does NOT return ``confirmed`` on the safe twin (no false positive).

Plus the safety properties: traffic stays on target, redirects are not
followed, responses are capped, disallowed headers and off-target paths are
rejected, and state-changing methods need an explicit opt-in.
"""

from __future__ import annotations

import pytest

from cairn.server import replay_validation as rv
from cairn.server.replay_validation import (
    ReplayError,
    ValidationTarget,
    execute_plan,
    packet_from_result,
    validate_request_headers,
    validate_request_path,
    validate_target_url,
)

from .lab_target import LabTarget


@pytest.fixture
def lab():
    with LabTarget() as target:
        yield target


def _target(lab, **kw) -> ValidationTarget:
    profiles = {
        "alice": {"headers": {"Cookie": "sid=alice-session"}},
        "bob": {"headers": {"Cookie": "sid=bob-session"}},
    }
    return ValidationTarget(base_url=lab.base_url, profiles=profiles, **kw)


# --------------------------------------------------------------------------
# One confirmed + one safe-twin assertion per oracle
# --------------------------------------------------------------------------


def test_sql_error_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"path": "/search?q=x%27"}, "baseline": {"path": "/search?q=x"}}},
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"path": "/search_safe?q=x%27"}, "baseline": {"path": "/search_safe?q=x"}}},
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_boolean_diff_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {
            "oracle": "boolean_diff",
            "requests": {
                "baseline": {"path": "/item?id=1"},
                "true": {"path": "/item?id=1%20AND%201%3D1"},
                "false": {"path": "/item?id=1%20AND%201%3D2"},
            },
        },
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {
            "oracle": "boolean_diff",
            "requests": {
                "baseline": {"path": "/item_safe?id=1"},
                "true": {"path": "/item_safe?id=1%20AND%201%3D1"},
                "false": {"path": "/item_safe?id=1%20AND%201%3D2"},
            },
        },
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_reflected_raw_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {
            "oracle": "reflected_raw",
            "reflected": "<b>__M__</b>",
            "requests": {"attack": {"path": "/greet?name=%3Cb%3E__M__%3C%2Fb%3E"}, "baseline": {"path": "/greet?name=friend"}},
        },
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {
            "oracle": "reflected_raw",
            "reflected": "<b>__M__</b>",
            "requests": {"attack": {"path": "/greet_safe?name=%3Cb%3E__M__%3C%2Fb%3E"}, "baseline": {"path": "/greet_safe?name=friend"}},
        },
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_computed_marker_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {"oracle": "computed_marker", "expect": "A*B", "requests": {"attack": {"path": "/render?tpl=%7B%7B__A__*__B__%7D%7D"}}},
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {"oracle": "computed_marker", "expect": "A*B", "requests": {"attack": {"path": "/echo?tpl=%7B%7B__A__*__B__%7D%7D"}}},
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_computed_marker_without_nonces_is_inconclusive(lab):
    # A payload that hardcodes numbers instead of the server nonces must not
    # be accepted even if the target happens to echo a matching value.
    out = execute_plan(
        {"oracle": "computed_marker", "expect": "A*B", "requests": {"attack": {"path": "/render?tpl=%7B%7B2*3%7D%7D"}}},
        _target(lab),
    )
    assert out["verdict"] == "inconclusive"


def test_file_signature_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {
            "oracle": "file_signature",
            "signature": "passwd",
            "requests": {"attack": {"path": "/file?name=..%2F..%2Fetc%2Fpasswd"}, "baseline": {"path": "/file?name=readme"}},
        },
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {
            "oracle": "file_signature",
            "signature": "passwd",
            "requests": {"attack": {"path": "/file_safe?name=..%2F..%2Fetc%2Fpasswd"}, "baseline": {"path": "/file_safe?name=readme"}},
        },
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_redirect_host_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {
            "oracle": "redirect_host",
            "redirect_host": "__M__.cairn-test.invalid",
            "requests": {"attack": {"path": "/go?next=http%3A%2F%2F__M__.cairn-test.invalid%2F"}},
        },
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {
            "oracle": "redirect_host",
            "redirect_host": "__M__.cairn-test.invalid",
            "requests": {"attack": {"path": "/go_safe?next=http%3A%2F%2F__M__.cairn-test.invalid%2F"}},
        },
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_access_control_idor_confirmed_and_safe(lab):
    confirmed = execute_plan(
        {
            "oracle": "access_control",
            "victim": "alice",
            "attacker": "bob",
            "marker": "invoice 7781",
            "requests": {"target": {"path": "/note?id=1"}},
        },
        _target(lab),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    safe = execute_plan(
        {
            "oracle": "access_control",
            "victim": "alice",
            "attacker": "bob",
            "marker": "invoice 7781",
            "requests": {"target": {"path": "/mynote?id=1"}},
        },
        _target(lab),
    )
    assert safe["verdict"] != "confirmed"


def test_ssrf_callback_confirmed_and_safe(lab):
    callback = {"advertise_host": "127.0.0.1", "bind_host": "127.0.0.1", "port": 0}
    confirmed = execute_plan(
        {"oracle": "ssrf_callback", "requests": {"attack": {"path": "/fetch?url=__CALLBACK__"}}},
        _target(lab, callback=callback),
    )
    assert confirmed["verdict"] == "confirmed", confirmed["reason"]

    # A target that never makes the outbound request yields inconclusive, never confirmed.
    inconclusive = execute_plan(
        {"oracle": "ssrf_callback", "requests": {"attack": {"path": "/search?q=__CALLBACK__"}}},
        _target(lab, callback=callback),
    )
    assert inconclusive["verdict"] != "confirmed"


# --------------------------------------------------------------------------
# Safety properties
# --------------------------------------------------------------------------


def test_redirects_are_not_followed(lab):
    # /bounce 302s to /seen; if we followed it the target would record a hit.
    out = execute_plan(
        {"oracle": "redirect_host", "redirect_host": "__M__.cairn-test.invalid",
         "requests": {"attack": {"path": "/bounce?to=%2Fseen"}}},
        _target(lab),
    )
    assert out["exchanges"][0]["status"] == 302
    assert lab.contacted_hosts == []


def test_oversized_response_is_truncated(lab):
    out = execute_plan(
        {"oracle": "file_signature", "signature": "passwd",
         "requests": {"attack": {"path": "/big"}, "baseline": {"path": "/file_safe?name=readme"}}},
        _target(lab),
    )
    attack = next(e for e in out["exchanges"] if e["name"] == "attack")
    assert attack["truncated"] is True
    assert len(attack["response_excerpt"]) <= rv.EVIDENCE_EXCERPT_CHARS


def test_state_changing_method_blocked_without_optin(lab):
    out = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"method": "DELETE", "path": "/note?id=1"}, "baseline": {"path": "/search?q=x"}}},
        _target(lab),
    )
    assert out["verdict"] == "error"
    assert lab.state_changes == []


def test_state_changing_method_allowed_with_optin(lab):
    out = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"method": "DELETE", "path": "/note?id=1"}, "baseline": {"path": "/search?q=x"}}},
        _target(lab, allow_state_changing=True),
    )
    # The point is that the opt-in actually let the DELETE reach the server;
    # the lab records every state-changing request it receives.
    assert lab.state_changes == ["/note?id=1"]
    assert out["verdict"] != "error"


def test_path_validation_rejects_off_target_and_bad_paths():
    for bad in ["http://evil/", "//evil/x", "/a b", "/a\\b", "relative", "/x\x00y"]:
        with pytest.raises(ReplayError):
            validate_request_path(bad)
    assert validate_request_path("/ok?x=1") == "/ok?x=1"


def test_header_allow_list():
    with pytest.raises(ReplayError):
        validate_request_headers({"Cookie": "sid=steal"})
    with pytest.raises(ReplayError):
        validate_request_headers({"Authorization": "Bearer x"})
    assert validate_request_headers({"X-Forwarded-For": "127.0.0.1"}) == {"X-Forwarded-For": "127.0.0.1"}


def test_target_url_rejects_link_local_and_credentials():
    with pytest.raises(ReplayError):
        validate_target_url("http://169.254.169.254/")
    with pytest.raises(ReplayError):
        validate_target_url("http://user:pass@127.0.0.1/")
    with pytest.raises(ReplayError):
        validate_target_url("ftp://127.0.0.1/")


def test_unknown_oracle_is_error(lab):
    out = execute_plan({"oracle": "magic", "requests": {"attack": {"path": "/"}}}, _target(lab))
    assert out["verdict"] == "error"


# --------------------------------------------------------------------------
# Proof-packet extraction
# --------------------------------------------------------------------------


def test_packet_is_built_only_for_confirmed(lab):
    confirmed = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"path": "/search?q=x%27"}, "baseline": {"path": "/search?q=x"}}},
        _target(lab),
    )
    packet = packet_from_result(confirmed, "audit.local")
    assert packet is not None
    assert "{host}" not in packet["request"]
    assert "audit.local" in packet["request"]

    not_repro = execute_plan(
        {"oracle": "sql_error", "requests": {"attack": {"path": "/search_safe?q=x%27"}, "baseline": {"path": "/search_safe?q=x"}}},
        _target(lab),
    )
    assert packet_from_result(not_repro, "audit.local") is None
