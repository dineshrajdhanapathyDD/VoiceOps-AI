"""Tests for the rule-based log analyzer."""

import pytest

from analyzer import (
    MAX_EVIDENCE_LINES,
    MAX_LOG_CHARS,
    RULES,
    SAMPLE_INCIDENTS,
    UNKNOWN_ERROR_TYPE,
    analyze_logs,
    generate_markdown_report,
)

SAMPLE_EXPECTATIONS = {
    "Lambda timeout": "lambda_timeout",
    "IAM access denied": "iam_access_denied",
    "API throttling": "api_throttling",
    "Database connection error": "database_connection",
}

# Additional log variants per category, beyond the bundled samples.
VARIANTS = {
    "lambda_timeout": [
        "2026-10-29T10:00:00Z abc Task timed out after 3.00 seconds",
        "REPORT RequestId: x Duration: 900000.00 ms Status: timeout",
        '{"errorType": "Sandbox.Timedout", "errorMessage": "RequestId: x Error: Task timed out"}',
    ],
    "iam_access_denied": [
        "An error occurred (AccessDeniedException) when calling the Invoke operation",
        "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation",
        "User: arn:aws:iam::123456789012:user/dev is not authorized to perform: "
        "dynamodb:PutItem with an explicit deny in a service control policy",
    ],
    "api_throttling": [
        "An error occurred (TooManyRequestsException) when calling the Invoke operation: Rate Exceeded.",
        "An error occurred (ProvisionedThroughputExceededException) when calling the PutItem operation",
        "API Gateway responded with status code 429",
        "An error occurred (RequestLimitExceeded) when calling the RunInstances operation",
    ],
    "database_connection": [
        "FATAL: too many connections for role \"app\"",
        "com.mysql.cj.jdbc.exceptions.CommunicationsException: Communications link failure",
        "ERROR 2003 (HY000): Can't connect to MySQL server on 'db.example.internal:3306' (110)",
        'FATAL: password authentication failed for user "app"',
        "Error: connect ETIMEDOUT 10.0.1.25:5432",
    ],
}


def test_every_rule_has_a_sample():
    assert {r.error_type for r in RULES} == set(SAMPLE_EXPECTATIONS.values())
    assert set(SAMPLE_INCIDENTS) == set(SAMPLE_EXPECTATIONS)


@pytest.mark.parametrize("sample_name,expected", SAMPLE_EXPECTATIONS.items())
def test_samples_detected(sample_name, expected):
    result = analyze_logs(SAMPLE_INCIDENTS[sample_name])
    assert result.error_type == expected
    assert result.is_known
    assert result.evidence, "known errors must include matching evidence lines"
    assert result.causes
    assert result.steps
    assert result.severity in {"Critical", "High", "Medium", "Low"}
    assert result.confidence == "High"
    assert result.other_detected == []


@pytest.mark.parametrize(
    "expected,log",
    [(k, v) for k, logs in VARIANTS.items() for v in logs],
)
def test_variants_detected(expected, log):
    result = analyze_logs(log)
    assert result.error_type == expected
    assert result.evidence == [log.strip()]


def test_evidence_only_contains_matching_lines():
    log = "INFO starting\nDEBUG noise\nTask timed out after 5.00 seconds\nINFO done"
    result = analyze_logs(log)
    assert result.evidence == ["Task timed out after 5.00 seconds"]


def test_evidence_is_capped():
    log = "\n".join(f"line {i} ThrottlingException Rate exceeded" for i in range(50))
    result = analyze_logs(log)
    assert len(result.evidence) == MAX_EVIDENCE_LINES


def test_case_insensitive_matching():
    assert analyze_logs("task TIMED OUT after 10 seconds").error_type == "lambda_timeout"


@pytest.mark.parametrize(
    "log",
    [
        "INFO Application started successfully\nINFO Processed 42 records",
        "Segmentation fault (core dumped)",
        "KeyError: 'customer_id'",
    ],
)
def test_unknown_errors_do_not_invent_cause(log):
    result = analyze_logs(log)
    assert result.error_type == UNKNOWN_ERROR_TYPE
    assert not result.is_known
    assert result.severity == "Unknown"
    assert result.confidence == "None"
    assert result.causes == []
    assert result.evidence == []
    assert result.steps, "unknown errors still get generic triage steps"


@pytest.mark.parametrize("log", ["", "   ", "\n\t\n", None])
def test_empty_input_rejected(log):
    with pytest.raises(ValueError):
        analyze_logs(log)


def test_multiple_categories_reports_primary_and_others():
    log = SAMPLE_INCIDENTS["Database connection error"] + "\nThrottlingException"
    result = analyze_logs(log)
    assert result.error_type == "database_connection"
    assert "API throttling / rate limiting" in result.other_detected


def test_oversized_input_is_truncated():
    log = "Task timed out after 3.00 seconds\n" + "x" * (MAX_LOG_CHARS + 10)
    result = analyze_logs(log)
    assert result.truncated_input
    assert result.error_type == "lambda_timeout"


def test_steps_are_read_only_suggestions():
    """Suggested commands must never mutate AWS resources."""
    mutating = ("delete-", "put-", "update-", "create-", "attach-", "detach-", "modify-", "terminate-")
    for rule in RULES:
        for step in rule.steps:
            lowered = step.lower()
            assert not any(verb in lowered for verb in mutating), step


@pytest.mark.parametrize("sample_name", SAMPLE_INCIDENTS)
def test_markdown_report_known(sample_name):
    result = analyze_logs(SAMPLE_INCIDENTS[sample_name])
    report = generate_markdown_report(result)
    assert report.startswith("# VoiceOps AI Incident Report")
    assert result.title in report
    assert result.severity in report
    assert "## Matching evidence" in report
    assert "## Possible causes" in report
    assert "## Recommended diagnostic steps" in report
    for line in result.evidence:
        assert line in report


def test_markdown_report_unknown():
    report = generate_markdown_report(analyze_logs("KeyError: 'customer_id'"))
    assert "Unrecognized error" in report
    assert "no root cause is suggested" in report
    assert "## General triage steps" in report


def test_markdown_report_fence_survives_backticks():
    result = analyze_logs("```\nTask timed out after 3.00 seconds ```")
    report = generate_markdown_report(result)
    assert "````text" in report


# --- Detection-quality regression tests -----------------------------------
# Each case below was misclassified or missed by the original analyzer.

REAL_WORLD_FORMATS = [
    # (log, expected_error_type)
    ('psycopg.OperationalError: connection to server at "db.internal" (10.0.0.9), port 5432 failed: '
     "Connection refused", "database_connection"),
    ("FATAL: sorry, too many clients already", "database_connection"),
    ("FATAL: the database system is starting up", "database_connection"),
    ("MongoServerSelectionError: connect ECONNREFUSED 10.0.0.7:27017", "database_connection"),
    ("ORA-12541: TNS:no listener", "database_connection"),
    ("pyodbc.OperationalError: ('HYT00', '[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]"
     "Login timeout expired (0) (SQLDriverConnect)')", "database_connection"),
    ("HTTP/1.1 429 Too Many Requests", "api_throttling"),
    ('{"statusCode": 429, "message": "Too Many Requests"}', "api_throttling"),
    ("ReasonCode: ReservedFunctionConcurrentInvocationLimitExceeded", "api_throttling"),
    ("<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>",
     "api_throttling"),
    ("User: arn:aws:sts::123456789012:assumed-role/r/s is not authorized to perform: kms:Decrypt "
     "because no resource-based policy allows the kms:Decrypt action", "iam_access_denied"),
    ("An error occurred (AuthorizationError) when calling the Publish operation", "iam_access_denied"),
]


@pytest.mark.parametrize("log,expected", REAL_WORLD_FORMATS)
def test_real_world_formats(log, expected):
    result = analyze_logs(log)
    assert result.error_type == expected
    assert result.confidence == "High"


def test_mysql_access_denied_is_database_not_iam():
    result = analyze_logs(
        "ERROR 1045 (28000): Access denied for user 'app'@'10.0.1.5' (using password: YES)"
    )
    assert result.error_type == "database_connection"
    assert "IAM access denied" not in result.other_detected


def test_s3_access_denied_is_still_iam():
    result = analyze_logs("<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>")
    assert result.error_type == "iam_access_denied"


@pytest.mark.parametrize(
    "log,expected",
    [
        ("Error 111 connecting to redis-cache:6379. Connection refused.", "database_connection"),
        ("INFO throttling disabled for internal clients", "api_throttling"),
        ("sqlite3.OperationalError: no such table: users", "database_connection"),
        ("Response 403 Forbidden from upstream", "iam_access_denied"),
    ],
)
def test_generic_signals_are_low_confidence(log, expected):
    result = analyze_logs(log)
    assert result.error_type == expected
    assert result.confidence == "Low"
    assert result.is_tentative


def test_generic_signal_with_context_raises_confidence():
    result = analyze_logs(
        "Connection refused while connecting to orders.abc.us-east-1.rds.amazonaws.com:5432"
    )
    assert result.error_type == "database_connection"
    assert result.confidence == "Medium"
    assert not result.is_tentative


def test_context_alone_does_not_detect():
    result = analyze_logs("INFO connected to postgres on port 5432, REPORT RequestId: abc")
    assert result.error_type == UNKNOWN_ERROR_TYPE


@pytest.mark.parametrize(
    "log",
    [
        "We noticed a slowdown in checkout latency",  # not the S3 SlowDown error code
        "REPORT RequestId: x Duration: 120.5 ms Billed Duration: 121 ms Status: success",
        "INFO Retrying request with backoff",
    ],
)
def test_no_false_positives(log):
    assert analyze_logs(log).error_type == UNKNOWN_ERROR_TYPE


def test_overlapping_patterns_are_not_double_counted():
    # "Throttling" inside "ThrottlingException" must not also count as the weak signal.
    result = analyze_logs("ThrottlingException")
    assert result.matched_signals == ["ThrottlingException error code"]
    assert result.score == 3


def test_lambda_timeout_wins_over_downstream_db_timeout():
    result = analyze_logs(
        "connection timed out to database orders-db\nTask timed out after 15.00 seconds"
    )
    assert result.error_type == "lambda_timeout"
    assert "Database connection failure" in result.other_detected


def test_evidence_prefers_strong_signal_lines_when_capped():
    noise = ["WARN throttling observed"] * 20
    log = "\n".join(noise + ["ERROR ThrottlingException: Rate exceeded"])
    result = analyze_logs(log)
    assert len(result.evidence) == MAX_EVIDENCE_LINES
    assert "ERROR ThrottlingException: Rate exceeded" in result.evidence


def test_matched_signals_are_reported():
    result = analyze_logs(SAMPLE_INCIDENTS["IAM access denied"])
    assert "AccessDenied error code" in result.matched_signals
    assert "No policy allows the action" in result.matched_signals


def test_report_marks_tentative_results():
    report = generate_markdown_report(analyze_logs("INFO throttling disabled"))
    assert "**Tentative:**" in report
    assert "**Matched signals:** Throttling mentioned" in report
    confident = generate_markdown_report(analyze_logs(SAMPLE_INCIDENTS["API throttling"]))
    assert "**Tentative:**" not in confident
