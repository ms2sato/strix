"""Specs for the lab-fork opt-in, conservative tool-output condenser.

No LLM calls. Verifies: findings/anomalies are never dropped, verbose bodies are
folded, unrecognized/small output fails open, the opt-in gate defaults off (and
is NOT turned on by profile auto-detection), and ``_bound_result`` always keeps
the full raw output (condensing only when it can be spilled first).
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from strix.agents.factory import _bound_result, _tool_output_parse_enabled
from strix.config import loader
from strix.tools import output_store
from strix.tools.output_condense import condense


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "STRIX_LAB_PROFILE", "STRIX_TOOL_OUTPUT_PARSE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


def _big_nuclei(n: int = 200) -> str:
    return "\n".join(
        json.dumps(
            {
                "template-id": f"cve-2021-{i}",
                "info": {"severity": "high", "name": f"X{i}"},
                "matched-at": f"https://web/{i}",
                "type": "http",
            }
        )
        for i in range(n)
    )


def _big_semgrep(n: int = 100) -> str:
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "rb.eval",
                    "path": "app/x.rb",
                    "start": {"line": i},
                    "extra": {"severity": "ERROR", "message": "use of eval " + "z" * 500},
                }
                for i in range(n)
            ],
            "errors": [],
        }
    )


# --- condense: keep findings, fold verbosity, fail open -----------------------


def test_nuclei_keeps_every_finding() -> None:
    text = _big_nuclei(200)
    out = condense(text)
    assert out is not None
    assert len(out) < len(text)
    assert out.count("[high]") == 200  # every finding preserved


def test_semgrep_keeps_every_result() -> None:
    text = _big_semgrep(100)
    out = condense(text)
    assert out is not None
    assert out.count("[ERROR]") == 100


def test_http_keeps_status_and_security_headers_and_folds_body() -> None:
    text = (
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/html\r\n"
        "Set-Cookie: s=1; HttpOnly\r\n"
        "X-Frame-Options: DENY\r\n\r\n" + ("A" * 20000)
    )
    out = condense(text)
    assert out is not None
    assert "500" in out  # non-2xx status preserved
    assert "Set-Cookie" in out and "X-Frame-Options" in out  # security headers kept
    assert "folded" in out and len(out) < len(text)  # body folded


def test_unknown_output_fails_open() -> None:
    assert condense("some unstructured log output " * 500) is None


def test_small_output_not_condensed() -> None:
    assert condense("HTTP/1.1 200 OK\r\n\r\nhi") is None


def test_unparseable_nuclei_lines_are_kept() -> None:
    # A real error line mixed with findings must never be dropped.
    text = "FATAL: could not resolve host\n" + _big_nuclei(150)
    out = condense(text)
    assert out is not None
    assert "FATAL: could not resolve host" in out


# --- gate: default off, not enabled by auto-detect ---------------------------


def test_parse_gate_off_by_default(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")  # anthropic, but no opt-in
    assert _tool_output_parse_enabled(loader.load_settings().context) is False


def test_parse_gate_explicit_env(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setenv("STRIX_TOOL_OUTPUT_PARSE", "1")
    assert _tool_output_parse_enabled(loader.load_settings().context) is True


def test_parse_gate_explicit_profile(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setenv("STRIX_LAB_PROFILE", "claude")
    assert _tool_output_parse_enabled(loader.load_settings().context) is True


# --- _bound_result: never loses data -----------------------------------------


async def test_bound_result_condenses_and_points_to_full(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_TOOL_OUTPUT_PARSE", "1")
    loader.load_settings()
    spilled: dict[str, str] = {}

    async def _writer(output_id: str, text: str) -> str:
        spilled["text"] = text
        return f"/workspace/.tool-output/{output_id}.txt"

    output_store.configure_spill_writer(_writer)
    try:
        text = _big_nuclei(200)
        out = await _bound_result(text)
    finally:
        output_store.configure_spill_writer(None)

    assert "nuclei:" in out  # condensed view
    assert "saved to /workspace/.tool-output/" in out  # pointer to full
    assert spilled["text"] == text  # the FULL raw output was spilled verbatim


async def test_bound_result_upstream_when_gate_off(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o")  # no opt-in, non-claude
    loader.load_settings()
    output_store.configure_spill_writer(None)
    text = _big_nuclei(200)
    out = await _bound_result(text)
    assert "nuclei:" not in out  # not condensed; upstream head/tail path


async def test_bound_result_no_spill_falls_back_without_condensing(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_TOOL_OUTPUT_PARSE", "1")
    loader.load_settings()
    output_store.configure_spill_writer(None)  # store_full -> None => must not condense
    text = _big_nuclei(200)
    out = await _bound_result(text)
    assert "nuclei:" not in out  # fell back to raw bounding; no data dropped
