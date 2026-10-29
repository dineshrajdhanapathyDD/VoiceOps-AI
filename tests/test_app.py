"""Headless UI tests for the Streamlit app using streamlit.testing."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from analyzer import SAMPLE_INCIDENTS

APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")


def _app() -> AppTest:
    at = AppTest.from_file(APP_PATH, default_timeout=30)
    at.run()
    assert not at.exception
    return at


def _button(at: AppTest, label: str):
    return next(b for b in at.button if b.label == label)


def test_app_loads():
    at = _app()
    assert at.title[0].value == "VoiceOps AI"
    assert at.text_area(key="log_input").value == ""


def test_empty_analysis_shows_error():
    at = _app()
    _button(at, "Analyze logs").click().run()
    assert not at.exception
    assert any("Paste some log text" in e.value for e in at.error)


@pytest.mark.parametrize("sample", SAMPLE_INCIDENTS)
def test_load_and_analyze_sample(sample):
    at = _app()
    at.selectbox(key="sample_choice").select(sample).run()
    _button(at, "Load sample").click().run()
    assert at.text_area(key="log_input").value == SAMPLE_INCIDENTS[sample]

    _button(at, "Analyze logs").click().run()
    assert not at.exception
    metric_values = [m.value for m in at.metric]
    assert "High" in metric_values  # confidence for bundled samples
    assert any(h.value.startswith("#### Recommended diagnostic steps") for h in at.markdown)


def test_unknown_error_shows_honest_warning():
    at = _app()
    at.text_area(key="log_input").input("KeyError: 'customer_id'").run()
    _button(at, "Analyze logs").click().run()
    assert not at.exception
    assert any("will not guess a root cause" in w.value for w in at.warning)


def test_clear_resets_input():
    at = _app()
    at.text_area(key="log_input").input("Task timed out after 3 seconds").run()
    _button(at, "Clear").click().run()
    assert at.text_area(key="log_input").value == ""


# --- Optional Bedrock panel -------------------------------------------------


def _analyzed_with_bedrock_enabled() -> AppTest:
    at = _app()
    at.toggle(key="bedrock_enabled").set_value(True).run()
    _button(at, "Load sample").click().run()
    _button(at, "Analyze logs").click().run()
    assert not at.exception
    return at


def test_bedrock_panel_hidden_by_default():
    at = _app()
    _button(at, "Load sample").click().run()
    _button(at, "Analyze logs").click().run()
    assert not any(b.label == "Explain with Bedrock" for b in at.button)


def test_bedrock_button_requires_consent(monkeypatch):
    import bedrock_client

    calls = []
    monkeypatch.setattr(bedrock_client, "explain_with_bedrock", lambda *a, **k: calls.append(1) or "x")

    at = _analyzed_with_bedrock_enabled()
    assert at.text_input(key="bedrock_model_id").value == bedrock_client.DEFAULT_MODEL_ID
    assert _button(at, "Explain with Bedrock").disabled
    assert calls == []


def test_bedrock_explain_flow_with_consent(monkeypatch):
    import bedrock_client

    captured = {}

    def fake_explain(logs, result, **kwargs):
        captured.update(logs=logs, result=result, **kwargs)
        return "### AI summary\nFake explanation. Try `aws lambda invoke`."

    monkeypatch.setattr(bedrock_client, "explain_with_bedrock", fake_explain)

    at = _analyzed_with_bedrock_enabled()
    at.checkbox(key="bedrock_consent").check().run()
    explain = _button(at, "Explain with Bedrock")
    assert not explain.disabled
    explain.click().run()

    assert not at.exception
    assert captured["logs"] == SAMPLE_INCIDENTS["Lambda timeout"]
    assert captured["redact_sensitive"] is True
    assert any("Fake explanation" in m.value for m in at.markdown)
    assert any("aws lambda invoke" in w.value for w in at.warning)

    # A new analysis clears the explanation and requires fresh consent.
    _button(at, "Analyze logs").click().run()
    assert not at.checkbox(key="bedrock_consent").value
    assert not any("Fake explanation" in m.value for m in at.markdown)


def test_bedrock_error_is_shown(monkeypatch):
    import bedrock_client

    def failing(*a, **k):
        raise bedrock_client.BedrockUnavailableError("No AWS credentials found.")

    monkeypatch.setattr(bedrock_client, "explain_with_bedrock", failing)

    at = _analyzed_with_bedrock_enabled()
    at.checkbox(key="bedrock_consent").check().run()
    _button(at, "Explain with Bedrock").click().run()
    assert not at.exception
    assert any("No AWS credentials" in e.value for e in at.error)


def test_tentative_result_shows_warning():
    at = _app()
    at.text_area(key="log_input").input("Error 111 connecting to redis:6379. Connection refused.").run()
    _button(at, "Analyze logs").click().run()
    assert not at.exception
    assert any("tentative" in w.value for w in at.warning)
    assert any("Matched signals: 'Connection refused' message" in c.value for c in at.caption)
