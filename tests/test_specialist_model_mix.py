"""Specs for the lab-fork opt-in per-agent model mix (opus root + sonnet specialist).

No LLM calls: these verify the gating logic, the per-agent ``model`` wiring, and
the SDK model-resolution precedence that made the global ``RunConfig.model``
override necessary — all offline.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from agents.run_config import RunConfig
from agents.run_internal.turn_preparation import get_model

from strix.agents.factory import build_strix_agent, claude_profile_enabled, make_child_factory
from strix.config import loader
from strix.config.models import StrixProvider


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("STRIX_LLM", "STRIX_LAB_PROFILE", "STRIX_SPECIALIST_LLM"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


def _child_model(scan_mode: str = "quick") -> str | None:
    child = make_child_factory(scan_mode=scan_mode)(name="spec", skills=[])
    return child.model


def _resolved_name(model: object) -> str | None:
    cur = model
    for _ in range(8):
        name = getattr(cur, "model", None)
        if isinstance(name, str):
            return name
        nxt = getattr(cur, "_inner", None) or getattr(cur, "_model", None)
        if nxt is None or nxt is cur:
            break
        cur = nxt
    return None


# --- gating -------------------------------------------------------------------


def test_profile_explicit_claude_enables(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setenv("STRIX_LAB_PROFILE", "claude")
    assert claude_profile_enabled() is True


def test_profile_explicit_other_value_disables(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LAB_PROFILE", "off")
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    assert claude_profile_enabled() is False


def test_profile_autodetect_anthropic(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    assert claude_profile_enabled() is True


def test_profile_autodetect_off_for_non_claude(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o")
    assert claude_profile_enabled() is False


# --- child/specialist model selection ----------------------------------------


def test_specialist_applied_under_profile(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    monkeypatch.setenv("STRIX_LAB_PROFILE", "claude")
    monkeypatch.setenv("STRIX_SPECIALIST_LLM", "anthropic/claude-sonnet-5")
    assert _child_model() == "anthropic/claude-sonnet-5"


def test_default_child_model_is_none_upstream(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    # No profile, no specialist => upstream behavior (child uses RunConfig model).
    assert _child_model() is None


def test_non_claude_specialist_is_guarded(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    monkeypatch.setenv("STRIX_LAB_PROFILE", "claude")
    monkeypatch.setenv("STRIX_SPECIALIST_LLM", "openai/gpt-4o")
    assert _child_model() is None


def test_specialist_ignored_when_profile_off(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    monkeypatch.setenv("STRIX_LAB_PROFILE", "off")
    monkeypatch.setenv("STRIX_SPECIALIST_LLM", "anthropic/claude-sonnet-5")
    assert _child_model() is None


def test_root_agent_model_defaults_none(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    root = build_strix_agent(name="root", skills=[], is_root=True, scan_mode="quick")
    assert root.model is None


# --- the SDK precedence the runner fix depends on -----------------------------


def test_per_agent_model_honored_when_runconfig_model_none(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    """With RunConfig.model=None (mix mode), each agent's own model is used."""
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    rc = RunConfig(model=None, model_provider=StrixProvider())
    root = build_strix_agent(
        name="root", skills=[], is_root=True, scan_mode="quick", model="anthropic/claude-opus-4-8"
    )
    child = build_strix_agent(
        name="spec", skills=[], is_root=False, scan_mode="quick", model="anthropic/claude-sonnet-5"
    )
    assert _resolved_name(get_model(root, rc)) == "anthropic/claude-opus-4-8"
    assert _resolved_name(get_model(child, rc)) == "anthropic/claude-sonnet-5"


def test_runconfig_model_str_globally_overrides_agent_model(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    """Regression guard: a str RunConfig.model overrides agent.model (upstream SDK
    behavior), which is exactly why the runner sets RunConfig.model=None for the mix."""
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-8")
    rc = RunConfig(model="anthropic/claude-opus-4-8", model_provider=StrixProvider())
    child = build_strix_agent(
        name="spec", skills=[], is_root=False, scan_mode="quick", model="anthropic/claude-sonnet-5"
    )
    assert _resolved_name(get_model(child, rc)) == "anthropic/claude-opus-4-8"
