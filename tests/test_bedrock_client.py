"""Tests for the optional Bedrock integration. No network calls are made."""

import pytest

import bedrock_client
from analyzer import SAMPLE_INCIDENTS, analyze_logs, generate_markdown_report
from bedrock_client import (
    MAX_LOG_CHARS_SENT,
    MAX_OUTPUT_TOKENS,
    BedrockUnavailableError,
    explain_with_bedrock,
    prepare_logs,
    redact,
)


class FakeClient:
    """Stand-in for a bedrock-runtime client that records calls."""

    def __init__(self, text="### Summary\nLooks like a timeout.", exc=None):
        self.text = text
        self.exc = exc
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return {"output": {"message": {"role": "assistant", "content": [{"text": self.text}]}}}


def _result(sample="Lambda timeout"):
    return analyze_logs(SAMPLE_INCIDENTS[sample])


def test_redaction_masks_sensitive_values():
    text = (
        "key=AKIAABCDEFGHIJKLMNOP user ops@example.com from 10.0.12.34 "
        "arn:aws:iam::123456789012:role/x password=hunter2 Authorization: Bearer abc.def.ghi"
    )
    out = redact(text)
    for secret in ("AKIAABCDEFGHIJKLMNOP", "ops@example.com", "10.0.12.34", "123456789012", "hunter2", "abc.def.ghi"):
        assert secret not in out
    assert "[REDACTED_ACCESS_KEY]" in out
    assert "[REDACTED_ACCOUNT]" in out


def test_redaction_keeps_error_text():
    line = "Task timed out after 30.01 seconds"
    assert redact(line) == line


def test_prepare_logs_without_redaction_is_unchanged():
    text = SAMPLE_INCIDENTS["IAM access denied"]
    assert prepare_logs(text, redact_sensitive=False) == text


def test_prepare_logs_truncates():
    out = prepare_logs("x" * (MAX_LOG_CHARS_SENT + 500), redact_sensitive=False)
    assert len(out) < MAX_LOG_CHARS_SENT + 100
    assert out.endswith("[... truncated by VoiceOps AI ...]")


def test_explain_sends_expected_request():
    client = FakeClient()
    logs = SAMPLE_INCIDENTS["IAM access denied"]
    text = explain_with_bedrock(logs, _result("IAM access denied"), model_id="m-1", region="us-east-1", client=client)

    assert text == "### Summary\nLooks like a timeout."
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["modelId"] == "m-1"
    assert call["inferenceConfig"]["maxTokens"] == MAX_OUTPUT_TOKENS
    assert "untrusted data" in call["system"][0]["text"]
    prompt = call["messages"][0]["content"][0]["text"]
    assert "<logs>" in prompt and "</logs>" in prompt
    assert "IAM access denied" in prompt
    assert "123456789012" not in prompt  # redacted by default


def test_explain_can_skip_redaction():
    client = FakeClient()
    logs = SAMPLE_INCIDENTS["IAM access denied"]
    explain_with_bedrock(logs, _result("IAM access denied"), redact_sensitive=False, client=client)
    assert "123456789012" in client.calls[0]["messages"][0]["content"][0]["text"]


def test_unknown_result_prompt_is_honest():
    client = FakeClient()
    result = analyze_logs("KeyError: 'customer_id'")
    explain_with_bedrock("KeyError: 'customer_id'", result, client=client)
    assert "did not recognize" in client.calls[0]["messages"][0]["content"][0]["text"]


def test_empty_logs_rejected_before_any_call():
    client = FakeClient()
    with pytest.raises(ValueError):
        explain_with_bedrock("  ", _result(), client=client)
    assert client.calls == []


def test_empty_response_raises():
    with pytest.raises(BedrockUnavailableError, match="empty"):
        explain_with_bedrock("Task timed out after 3 seconds", _result(), client=FakeClient(text="  "))


@pytest.mark.parametrize(
    "code,expected",
    [
        ("AccessDeniedException", "Access denied"),
        ("ResourceNotFoundException", "model ID"),
        ("ValidationException", "model ID"),
        ("ThrottlingException", "throttling"),
        ("ExpiredTokenException", "expired"),
    ],
)
def test_client_errors_are_friendly(code, expected):
    botocore_exceptions = pytest.importorskip("botocore.exceptions")
    exc = botocore_exceptions.ClientError({"Error": {"Code": code, "Message": "x"}}, "Converse")
    with pytest.raises(BedrockUnavailableError, match=expected):
        explain_with_bedrock("Task timed out after 3 seconds", _result(), client=FakeClient(exc=exc))


def test_no_credentials_error_is_friendly():
    botocore_exceptions = pytest.importorskip("botocore.exceptions")
    with pytest.raises(BedrockUnavailableError, match="No AWS credentials"):
        explain_with_bedrock(
            "Task timed out after 3 seconds",
            _result(),
            client=FakeClient(exc=botocore_exceptions.NoCredentialsError()),
        )


def test_missing_boto3_is_friendly(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3" or name.startswith("botocore"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert not bedrock_client.boto3_available()
    with pytest.raises(BedrockUnavailableError, match="boto3 is not installed"):
        explain_with_bedrock("Task timed out after 3 seconds", _result())


def test_report_includes_ai_section_only_when_present():
    result = _result()
    assert "AI explanation" not in generate_markdown_report(result)
    report = generate_markdown_report(result, ai_explanation="Model says hi", ai_model_id="m-1")
    assert "## AI explanation (Amazon Bedrock, model `m-1`)" in report
    assert "Model says hi" in report
    assert "Verify before acting" in report


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Use `aws lambda invoke` with a test event", ["aws lambda invoke"]),
        ("Run aws iam attach-role-policy --role-name x", ["aws iam attach-role-policy"]),
        ("aws ec2 terminate-instances and aws rds reboot-db-instance",
         ["aws ec2 terminate-instances", "aws rds reboot-db-instance"]),
        ("aws s3 rm s3://b/k then aws dynamodb delete-table --table-name t",
         ["aws s3 rm", "aws dynamodb delete-table"]),
        ("aws s3 sync . s3://b", ["aws s3 sync"]),
    ],
)
def test_risky_commands_flagged(text, expected):
    assert bedrock_client.find_risky_commands(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "aws lambda get-function-configuration --function-name x",
        "aws sts get-caller-identity",
        "aws iam simulate-principal-policy --policy-source-arn a",
        "aws logs start-query --log-group-name g",
        "aws rds describe-db-instances",
        "aws s3 ls s3://bucket",
        "",
    ],
)
def test_read_only_commands_not_flagged(text):
    assert bedrock_client.find_risky_commands(text) == []


def test_report_includes_ai_warning():
    report = generate_markdown_report(
        _result(), ai_explanation="Try aws lambda invoke", ai_warnings=["aws lambda invoke"]
    )
    assert "**Warning:**" in report
    assert "`aws lambda invoke`" in report


# --- Credentials for hosted deployments (Streamlit secrets) -----------------

FAKE_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example values
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ({}, None),
        ({"aws_access_key_id": FAKE_KEY_ID}, None),  # half a key pair falls back
        (
            {"aws_access_key_id": FAKE_KEY_ID, "aws_secret_access_key": FAKE_SECRET, "region": "us-east-1"},
            {"aws_access_key_id": FAKE_KEY_ID, "aws_secret_access_key": FAKE_SECRET},
        ),
        (
            {"AWS_ACCESS_KEY_ID": f" {FAKE_KEY_ID} ", "AWS_SECRET_ACCESS_KEY": FAKE_SECRET, "AWS_SESSION_TOKEN": "tok"},
            {"aws_access_key_id": FAKE_KEY_ID, "aws_secret_access_key": FAKE_SECRET, "aws_session_token": "tok"},
        ),
        ("not a mapping", None),
    ],
)
def test_normalize_credentials(raw, expected):
    assert bedrock_client.normalize_credentials(raw) == expected


def test_explicit_credentials_used_for_session(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    captured = {}

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session"] = kwargs

        def client(self, service, **kwargs):
            captured["service"] = service
            captured["region"] = kwargs["region_name"]
            return FakeClient()

    monkeypatch.setattr(boto3, "Session", FakeSession)
    creds = {"aws_access_key_id": FAKE_KEY_ID, "aws_secret_access_key": FAKE_SECRET}
    explain_with_bedrock("Task timed out after 3 seconds", _result(), region="us-west-2", credentials=creds)
    assert captured == {"session": creds, "service": "bedrock-runtime", "region": "us-west-2"}


def test_default_credential_chain_when_no_credentials(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    captured = {}

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session"] = kwargs

        def client(self, service, **kwargs):
            return FakeClient()

    monkeypatch.setattr(boto3, "Session", FakeSession)
    explain_with_bedrock("Task timed out after 3 seconds", _result())
    assert captured["session"] == {}


def test_real_session_carries_explicit_keys():
    pytest.importorskip("boto3")
    client = bedrock_client._make_client(
        "us-east-1", {"aws_access_key_id": FAKE_KEY_ID, "aws_secret_access_key": FAKE_SECRET}
    )
    assert client.meta.region_name == "us-east-1"
    assert client._request_signer._credentials.access_key == FAKE_KEY_ID


def test_no_credentials_message_mentions_streamlit_secrets():
    botocore_exceptions = pytest.importorskip("botocore.exceptions")
    with pytest.raises(BedrockUnavailableError, match="App settings > Secrets"):
        explain_with_bedrock(
            "Task timed out after 3 seconds",
            _result(),
            client=FakeClient(exc=botocore_exceptions.NoCredentialsError()),
        )


def test_invalid_keys_message():
    botocore_exceptions = pytest.importorskip("botocore.exceptions")
    exc = botocore_exceptions.ClientError({"Error": {"Code": "UnrecognizedClientException"}}, "Converse")
    with pytest.raises(BedrockUnavailableError, match="rejected the credentials"):
        explain_with_bedrock("Task timed out after 3 seconds", _result(), client=FakeClient(exc=exc))
