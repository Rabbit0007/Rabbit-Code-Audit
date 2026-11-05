"""The index should surface web sinks (XXE, SSTI, open redirect) tied to input.

These exercise the real source->sink extraction used during import.  A signal is
only produced when an untrusted input reaches the sink, so each snippet wires a
request value into the dangerous call; a safe snippet with no input must stay
silent.
"""

from __future__ import annotations

from cairn.server.source_service import _extract_risk_signals, _risk_signal_candidate_severity


def _categories(text: str) -> set[str]:
    return {signal.category for signal in _extract_risk_signals(text)}


def _severity(text: str, category: str) -> str:
    signal = next(s for s in _extract_risk_signals(text) if s.category == category)
    return _risk_signal_candidate_severity(signal)


def test_xxe_php_loadxml_is_detected_high():
    text = """<?php
$xml = $_GET['data'];
$doc = new DOMDocument();
$doc->loadXML($xml);
"""
    assert "XML 外部实体解析能力" in _categories(text)
    assert _severity(text, "XML 外部实体解析能力") == "high"


def test_ssti_flask_render_template_string_is_detected_high():
    text = """from flask import request, render_template_string
name = request.args.get('name')
page = render_template_string("Hello " + name)
"""
    assert "模板/表达式渲染能力" in _categories(text)
    assert _severity(text, "模板/表达式渲染能力") == "high"


def test_open_redirect_flask_is_detected_medium():
    text = """from flask import request, redirect
nxt = request.args.get('next')
return redirect(nxt)
"""
    assert "重定向跳转能力" in _categories(text)
    assert _severity(text, "重定向跳转能力") == "medium"


def test_open_redirect_express_is_detected():
    text = """app.get('/go', function (req, res) {
  const dest = req.query.url;
  res.redirect(dest);
});
"""
    assert "重定向跳转能力" in _categories(text)


def test_no_signal_without_untrusted_input():
    # A hardcoded redirect / static template must not produce a sink signal.
    text = """from flask import redirect, render_template_string
def home():
    page = render_template_string("static page")
    return redirect("/home")
"""
    categories = _categories(text)
    assert "重定向跳转能力" not in categories
    assert "模板/表达式渲染能力" not in categories
