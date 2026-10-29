"""VoiceOps AI - Streamlit dashboard for rule-based AWS incident log analysis."""

from __future__ import annotations

import streamlit as st

import bedrock_client
from analyzer import (
    MAX_LOG_CHARS,
    SAMPLE_INCIDENTS,
    TENTATIVE_NOTE,
    AnalysisResult,
    analyze_logs,
    generate_markdown_report,
)

SEVERITY_BADGES = {
    "Critical": ":red-background[**Critical**]",
    "High": ":orange-background[**High**]",
    "Medium": ":blue-background[**Medium**]",
    "Low": ":green-background[**Low**]",
    "Unknown": ":gray-background[**Unknown**]",
}

LOG_KEY = "log_input"
RESULT_KEY = "analysis_result"
ANALYZED_LOGS_KEY = "analyzed_logs"
AI_KEY = "ai_explanation"
AI_MODEL_KEY = "ai_model_used"
AI_ERROR_KEY = "ai_error"


def _reset_results() -> None:
    # Consent is reset too, so each new set of logs needs a fresh opt-in.
    for key in (RESULT_KEY, ANALYZED_LOGS_KEY, AI_KEY, AI_MODEL_KEY, AI_ERROR_KEY, "bedrock_consent"):
        st.session_state.pop(key, None)


def _load_sample() -> None:
    choice = st.session_state.get("sample_choice")
    if choice in SAMPLE_INCIDENTS:
        st.session_state[LOG_KEY] = SAMPLE_INCIDENTS[choice]
        _reset_results()


def _clear() -> None:
    st.session_state[LOG_KEY] = ""
    _reset_results()


def _run_analysis() -> None:
    text = st.session_state.get(LOG_KEY, "")
    _reset_results()
    try:
        st.session_state[RESULT_KEY] = analyze_logs(text)
        # Freeze the analyzed text so Bedrock explains exactly what was analyzed.
        st.session_state[ANALYZED_LOGS_KEY] = text
    except ValueError:
        st.session_state["input_error"] = "Paste some log text or load a sample first."


def _run_bedrock() -> None:
    """Explicit user action: send the prepared logs to Amazon Bedrock."""
    st.session_state.pop(AI_ERROR_KEY, None)
    result = st.session_state.get(RESULT_KEY)
    logs = st.session_state.get(ANALYZED_LOGS_KEY, "")
    if result is None or not st.session_state.get("bedrock_consent"):
        return
    model_id = st.session_state.get("bedrock_model_id", bedrock_client.DEFAULT_MODEL_ID)
    try:
        st.session_state[AI_KEY] = bedrock_client.explain_with_bedrock(
            logs,
            result,
            model_id=model_id,
            region=st.session_state.get("bedrock_region", bedrock_client.DEFAULT_REGION),
            redact_sensitive=st.session_state.get("bedrock_redact", True),
        )
        st.session_state[AI_MODEL_KEY] = model_id
    except (bedrock_client.BedrockUnavailableError, ValueError) as exc:
        st.session_state[AI_ERROR_KEY] = str(exc)


def render_sidebar() -> None:
    with st.sidebar:
        st.header("Sample incidents")
        st.selectbox("Choose a sample", list(SAMPLE_INCIDENTS), key="sample_choice")
        st.button("Load sample", on_click=_load_sample, width="stretch")

        st.divider()
        st.subheader("Amazon Bedrock (optional)")
        st.toggle("Enable AI explanation", key="bedrock_enabled", value=False)
        if st.session_state.get("bedrock_enabled"):
            st.text_input("Model ID", value=bedrock_client.DEFAULT_MODEL_ID, key="bedrock_model_id")
            st.text_input("Region", value=bedrock_client.DEFAULT_REGION, key="bedrock_region")
            st.caption("Uses your local AWS credentials. Nothing is sent until you click the explain button.")
            if not bedrock_client.boto3_available():
                st.warning("boto3 is not installed. Run `pip install -r requirements-bedrock.txt`.")

        st.divider()
        st.subheader("Privacy and safety")
        st.markdown(
            "- Analysis runs locally with Python rules.\n"
            "- No AWS credentials or AI API key needed for the core analyzer.\n"
            "- Logs are only sent to Amazon Bedrock if you enable it and click explain.\n"
            "- Commands are suggestions only. Nothing is executed and no AWS resources "
            "are changed."
        )


def render_bedrock_panel() -> None:
    st.markdown("#### AI explanation (Amazon Bedrock)")
    logs = st.session_state.get(ANALYZED_LOGS_KEY, "")

    st.checkbox(
        "Redact secrets, emails, IP addresses, and account IDs before sending",
        value=True,
        key="bedrock_redact",
    )
    preview = bedrock_client.prepare_logs(logs, st.session_state.get("bedrock_redact", True))
    with st.expander(f"Preview exactly what will be sent ({len(preview):,} characters)"):
        st.code(preview, language="text")

    st.checkbox(
        "I understand these logs will be sent to Amazon Bedrock in my AWS account, "
        "which may incur charges.",
        key="bedrock_consent",
    )
    st.button(
        "Explain with Bedrock",
        on_click=_run_bedrock,
        disabled=not st.session_state.get("bedrock_consent"),
    )

    error = st.session_state.get(AI_ERROR_KEY)
    if error:
        st.error(error)

    explanation = st.session_state.get(AI_KEY)
    if explanation:
        risky = bedrock_client.find_risky_commands(explanation)
        if risky:
            st.warning(
                "The AI response mentions commands that can change resources or run workloads. "
                "Do not run them as diagnostic steps: " + ", ".join(f"`{c}`" for c in risky)
            )
        st.caption(f"AI-generated by `{st.session_state.get(AI_MODEL_KEY)}`. Verify before acting.")
        with st.container(border=True):
            st.markdown(explanation)


def render_result(result: AnalysisResult) -> None:
    st.divider()
    st.subheader("Analysis")

    if result.truncated_input:
        st.warning(f"Input exceeded {MAX_LOG_CHARS:,} characters, so only the first part was analyzed.")

    col1, col2, col3 = st.columns(3)
    col1.metric("Detected error type", result.title)
    with col2:
        st.caption("Severity (rule-based estimate)")
        st.markdown(SEVERITY_BADGES.get(result.severity, result.severity))
    col3.metric("Confidence", result.confidence)

    if result.is_tentative:
        st.warning(TENTATIVE_NOTE)

    if result.other_detected:
        st.info("Also detected: " + ", ".join(result.other_detected))

    if not result.is_known:
        st.warning(
            "VoiceOps AI did not recognize this error. It will not guess a root cause. "
            "Use the general triage steps below to investigate manually."
        )

    left, right = st.columns(2)
    with left:
        st.markdown("#### Matching evidence")
        if result.evidence:
            st.code("\n".join(result.evidence), language="text")
            st.caption("Matched signals: " + "; ".join(result.matched_signals))
        else:
            st.caption("No log lines matched a known error pattern.")

        st.markdown("#### Possible causes")
        if result.causes:
            st.markdown("\n".join(f"- {c}" for c in result.causes))
        else:
            st.caption("No cause suggested for unrecognized errors.")

    with right:
        heading = "Recommended diagnostic steps" if result.is_known else "General triage steps"
        st.markdown(f"#### {heading}")
        st.markdown("\n".join(f"{i}. {s}" for i, s in enumerate(result.steps, start=1)))
        st.caption("Review every command before running it yourself. These are read-only checks.")

    if st.session_state.get("bedrock_enabled"):
        st.divider()
        render_bedrock_panel()

    st.divider()
    st.download_button(
        "Download Markdown report",
        data=generate_markdown_report(
            result,
            ai_explanation=st.session_state.get(AI_KEY),
            ai_model_id=st.session_state.get(AI_MODEL_KEY),
            ai_warnings=bedrock_client.find_risky_commands(st.session_state.get(AI_KEY) or ""),
        ),
        file_name=f"voiceops-incident-{result.error_type}.md",
        mime="text/markdown",
        type="primary",
    )


def main() -> None:
    st.set_page_config(page_title="VoiceOps AI", page_icon=":material/troubleshoot:", layout="wide")

    st.title("VoiceOps AI")
    st.caption(
        "Understand AWS-style incident logs and find safe troubleshooting steps. "
        "Built for the WeMakeDevs x Wispr Flow No Hands Challenge."
    )

    render_sidebar()

    st.text_area(
        "Incident logs",
        key=LOG_KEY,
        height=260,
        placeholder="Paste CloudWatch, Lambda, or application logs here...",
    )

    b1, b2, _ = st.columns([2, 1, 4])
    b1.button("Analyze logs", on_click=_run_analysis, type="primary", width="stretch")
    b2.button("Clear", on_click=_clear, width="stretch")

    error = st.session_state.pop("input_error", None)
    if error:
        st.error(error)

    result = st.session_state.get(RESULT_KEY)
    if result is not None:
        render_result(result)


if __name__ == "__main__":
    main()
