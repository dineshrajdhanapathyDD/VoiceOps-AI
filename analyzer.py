"""Rule-based analyzer for AWS-style incident logs.

This module has no network access, needs no AWS credentials, and never
executes commands. It only matches log text against local regex rules and
returns suggested *diagnostic* steps for a human to review.

Detection model
---------------
Each rule has two kinds of evidence:

* Signals: regexes for error messages. A *strong* signal is specific enough
  to identify the category on its own (for example ``ThrottlingException``).
  A *weak* signal is generic text that only hints at the category (for
  example ``Connection refused``, which also appears for Redis or HTTP).
* Context: regexes for surrounding clues (database ports, ``REPORT
  RequestId`` lines, ``assumed-role`` ARNs). Context never triggers a
  detection by itself; it only adds weight when a signal already matched.

Each distinct signal is counted once, no matter how many lines it matches.
The rule with the highest score wins. Confidence comes from the score and
whether any strong signal matched, so generic-only matches are reported as
Low confidence instead of being presented as a confident diagnosis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Guard against accidentally pasting enormous files into the analyzer.
MAX_LOG_CHARS = 500_000
MAX_EVIDENCE_LINES = 10
MAX_EVIDENCE_LINE_CHARS = 300

UNKNOWN_ERROR_TYPE = "unknown"

STRONG_WEIGHT = 3
WEAK_WEIGHT = 1
CONTEXT_WEIGHT = 1
MAX_CONTEXT_BONUS = 2
# Without a strong signal, a rule needs this score for Medium confidence.
MEDIUM_SCORE = 2
# Without a strong signal, a rule needs this score for High confidence.
HIGH_SCORE_WITHOUT_STRONG = 4


@dataclass(frozen=True)
class Signal:
    """One error-message pattern and how much it should be trusted."""

    label: str
    pattern: str
    strong: bool = True

    @property
    def weight(self) -> int:
        return STRONG_WEIGHT if self.strong else WEAK_WEIGHT


def strong(label: str, pattern: str) -> Signal:
    return Signal(label, pattern, strong=True)


def weak(label: str, pattern: str) -> Signal:
    return Signal(label, pattern, strong=False)


@dataclass(frozen=True)
class Rule:
    """A detection rule for one error category."""

    error_type: str
    title: str
    severity: str
    signals: tuple[Signal, ...]
    causes: tuple[str, ...]
    steps: tuple[str, ...]
    context: tuple[str, ...] = ()


@dataclass
class AnalysisResult:
    """Outcome of analyzing a block of log text."""

    error_type: str
    title: str
    severity: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    matched_signals: list[str] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    other_detected: list[str] = field(default_factory=list)
    score: int = 0
    truncated_input: bool = False
    analyzed_at: str = ""

    @property
    def is_known(self) -> bool:
        return self.error_type != UNKNOWN_ERROR_TYPE

    @property
    def is_tentative(self) -> bool:
        """True when only generic signals matched."""
        return self.is_known and self.confidence == "Low"


DB_PORTS = r"(?:3306|5432|1433|1521|27017)"

RULES: tuple[Rule, ...] = (
    Rule(
        error_type="lambda_timeout",
        title="AWS Lambda timeout",
        severity="High",
        signals=(
            strong("Lambda 'Task timed out' message", r"Task timed out after \d+(?:\.\d+)? seconds"),
            strong("Sandbox.Timedout error", r"\bSandbox\.Timedout\b"),
            strong("REPORT line with timeout status", r"\bStatus:\s*timeout\b"),
            weak("Lambda mentioned with a timeout", r"\bLambda\b.*\btim(?:ed|e)[\s-]?out\b"),
        ),
        context=(
            r"\bREPORT RequestId:",
            r"\bBilled Duration:",
            r"/aws/lambda/",
        ),
        causes=(
            "The function's configured timeout is shorter than the work it performs.",
            "A downstream call (HTTP API, database, another AWS service) is slow or hanging.",
            "A Lambda in a VPC cannot reach the internet or an AWS endpoint, so calls hang "
            "until timeout (missing NAT gateway or VPC endpoint).",
            "Insufficient memory, which also limits CPU and slows execution.",
            "Cold-start initialization work (large dependencies, connection setup) is too slow.",
        ),
        steps=(
            "Note the 'Duration' and 'Max Memory Used' values on the REPORT line and compare "
            "them to the configured timeout and memory size.",
            "Review the function configuration (read-only): "
            "`aws lambda get-function-configuration --function-name <name>`.",
            "Check CloudWatch metrics for Duration, Errors, and Throttles around the incident time.",
            "If the function runs in a VPC, verify its subnets have a route to required "
            "endpoints (NAT gateway or VPC endpoints).",
            "Add timing logs around downstream calls, or enable AWS X-Ray tracing, to find "
            "which call is slow.",
            "Confirm downstream clients use explicit timeouts shorter than the Lambda timeout.",
        ),
    ),
    Rule(
        error_type="iam_access_denied",
        title="IAM access denied",
        severity="High",
        signals=(
            strong("AccessDenied error code", r"\bAccessDenied(?:Exception)?\b"),
            strong("'is not authorized to perform' message", r"\bis not authorized to perform\b"),
            strong("UnauthorizedOperation error code", r"\bUnauthorizedOperation\b"),
            strong("Explicit deny in a policy", r"\bwith an explicit deny\b"),
            strong(
                "No policy allows the action",
                r"\bno (?:identity-based|resource-based|session|permissions boundary) policy allows\b",
            ),
            strong("AuthorizationError error code", r"\(AuthorizationError(?:Exception)?\)"),
            # MySQL uses "Access denied for user ..." for database logins; exclude it here.
            weak("'Access Denied' message", r"\bAccess Denied\b(?!\s+for\s+user)"),
            weak("HTTP 403 Forbidden", r"\b403\b.*\bForbidden\b|\bForbidden\b.*\b403\b"),
        ),
        context=(
            r"\barn:aws[\w-]*:(?:iam|sts)::",
            r"\bassumed-role/",
            # IAM action such as "s3:GetObject on"; case-sensitive to stay specific.
            r"(?-i:\b[a-z0-9-]+:[A-Z][A-Za-z]+ (?:on|action)\b)",
        ),
        causes=(
            "The IAM role or user lacks a policy that allows the action on the resource.",
            "An explicit Deny in an identity policy, resource policy, permissions boundary, "
            "or Service Control Policy (SCP) overrides an Allow.",
            "A resource-based policy (S3 bucket policy, KMS key policy) does not grant access "
            "to the calling principal.",
            "The code is running under a different principal than expected "
            "(wrong role, profile, or assumed-role session).",
            "Condition keys in the policy (source IP, VPC endpoint, MFA, tags) are not satisfied.",
        ),
        steps=(
            "Identify the exact principal ARN, action, and resource ARN from the error message.",
            "Confirm the caller identity in the affected environment: `aws sts get-caller-identity`.",
            "List policies attached to the role (read-only): "
            "`aws iam list-attached-role-policies --role-name <role>`.",
            "Test the permission without making changes: "
            "`aws iam simulate-principal-policy --policy-source-arn <principal-arn> "
            "--action-names <action> --resource-arns <resource-arn>`.",
            "If the error mentions an explicit deny, review SCPs, permissions boundaries, "
            "and resource policies.",
            "Search CloudTrail for the denied event to see the full request context.",
        ),
    ),
    Rule(
        error_type="api_throttling",
        title="API throttling / rate limiting",
        severity="Medium",
        signals=(
            strong("ThrottlingException error code", r"\bThrottlingException\b"),
            strong("TooManyRequestsException error code", r"\bTooManyRequestsException\b"),
            strong(
                "Throughput exceeded error code",
                r"\bProvisionedThroughputExceededException\b|\bThroughput exceeds the current capacity\b",
            ),
            strong("RequestLimitExceeded error code", r"\bRequestLimitExceeded\b"),
            strong("'Rate exceeded' message", r"\bRate exceeded\b"),
            # Case-sensitive so the ordinary word "slowdown" does not match.
            strong("S3 SlowDown error", r"(?-i:\bSlowDown\b)|\bPlease reduce your request rate\b"),
            strong("Lambda concurrency limit exceeded", r"ConcurrentInvocationLimitExceeded\b"),
            strong("HTTP 429 Too Many Requests", r"\b429 Too Many Requests\b"),
            strong(
                "HTTP 429 status code",
                r"(?:\bstatus(?:[\s_-]*code)?|\bHTTP(?:/\d(?:\.\d)?)?)[\"'\s:=]*429\b",
            ),
            weak("Throttling mentioned", r"\bthrottl(?:ed|ing)\b"),
            weak("LimitExceededException error code", r"\bLimitExceededException\b"),
        ),
        context=(
            r"\bretr(?:y|ying|ied|ies)\b",
            r"\bbackoff\b",
        ),
        causes=(
            "Request rate exceeds the service quota or API rate limit for the account or Region.",
            "A burst of traffic or a retry storm (retries without backoff) is amplifying load.",
            "Many clients or Lambda concurrent executions call the same API at once.",
            "DynamoDB table or index capacity is insufficient for the current traffic pattern.",
        ),
        steps=(
            "Identify the throttled service and API operation from the error message.",
            "Check CloudWatch metrics for throttled requests and call volume around the incident time.",
            "Review the applicable quota (read-only): "
            "`aws service-quotas list-service-quotas --service-code <code>`.",
            "Confirm the SDK client uses retries with exponential backoff and jitter.",
            "Look for retry loops or fan-out patterns that multiply requests during failures.",
            "For DynamoDB, review consumed versus provisioned capacity and hot partition keys.",
        ),
    ),
    Rule(
        error_type="database_connection",
        title="Database connection failure",
        severity="Critical",
        signals=(
            strong(
                "PostgreSQL could not connect",
                r"\bcould not connect to server\b|\bconnection to server at .+ failed\b",
            ),
            strong("MySQL could not connect", r"\bCan't connect to MySQL server\b|\bUnknown MySQL server host\b"),
            strong("JDBC communications link failure", r"\bCommunications link failure\b"),
            strong(
                "Database authentication failed",
                r"\bpassword authentication failed\b|\bAccess denied for user\s+'[^']*'@",
            ),
            strong(
                "Database connection limit reached",
                r"\btoo many (?:connections|clients)\b|\bremaining connection slots are reserved\b",
            ),
            strong(
                "Database not accepting connections",
                r"\bthe database system is (?:starting up|shutting down|in recovery mode)\b",
            ),
            strong(
                "Connection error on a database port",
                rf"\b(?:ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH)\b.*:{DB_PORTS}\b",
            ),
            strong("MongoDB/DocumentDB connection error", r"\bMongo(?:ServerSelection|Network|Timeout)Error\b"),
            strong("SQL Server connection error", r"\bLogin timeout expired\b|\berror occurred while establishing a connection to SQL Server\b"),
            strong("Oracle listener error", r"\bORA-(?:12170|12514|12541)\b"),
            weak("'Connection refused' message", r"\bConnection refused\b"),
            weak("Driver OperationalError", r"\bOperationalError\b"),
            weak("Connection timed out", r"\bconnection (?:timed out|timeout)\b"),
        ),
        context=(
            rf"\b{DB_PORTS}\b",
            r"\.(?:rds|docdb)\.amazonaws\.com\b",
            r"\b(?:postgres(?:ql)?|psql|mysql|mariadb|aurora|jdbc|psycopg2?|sqlalchemy|pymysql|mongo(?:db)?|database|rds)\b",
        ),
        causes=(
            "Security group or network ACL does not allow traffic from the application to the "
            "database port.",
            "The database endpoint, port, or DNS name in the configuration is incorrect.",
            "The database has reached its maximum connection limit "
            "(often from Lambda concurrency without connection pooling).",
            "Credentials are wrong, expired, or were rotated without updating the application.",
            "The database instance is stopped, rebooting, failing over, or under heavy load.",
        ),
        steps=(
            "Confirm the endpoint and port the application is using match the database instance.",
            "Check instance status (read-only): "
            "`aws rds describe-db-instances --db-instance-identifier <id>`.",
            "Verify the database security group allows inbound traffic on the database port "
            "from the application's security group or subnet.",
            "Check the DatabaseConnections and CPUUtilization CloudWatch metrics around the "
            "incident time.",
            "If the error mentions authentication, verify which secret or credential source the "
            "application reads and whether it was recently rotated.",
            "For Lambda workloads, consider whether RDS Proxy or connection reuse is needed.",
        ),
    ),
)

UNKNOWN_STEPS: tuple[str, ...] = (
    "Confirm the pasted logs cover the time window of the incident.",
    "Look for the first ERROR, Exception, or stack trace line, not just the last one.",
    "Note the AWS service, request ID, and resource names involved.",
    "Search the exact error message in the relevant AWS service documentation.",
    "Check CloudWatch metrics and recent deployments or configuration changes around the "
    "incident time.",
)

SEVERITY_ORDER = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


@dataclass(frozen=True)
class _CompiledRule:
    rule: Rule
    signals: tuple[tuple[Signal, re.Pattern[str]], ...]
    context: tuple[re.Pattern[str], ...]


_COMPILED_RULES: tuple[_CompiledRule, ...] = tuple(
    _CompiledRule(
        rule=rule,
        signals=tuple((s, re.compile(s.pattern, re.IGNORECASE)) for s in rule.signals),
        context=tuple(re.compile(c, re.IGNORECASE) for c in rule.context),
    )
    for rule in RULES
)


@dataclass
class _Match:
    rule: Rule
    score: int
    has_strong: bool
    signals: list[Signal]
    evidence: list[str]


def get_rule(error_type: str) -> Rule | None:
    """Return the rule for an error type, or None if it does not exist."""
    return next((r for r in RULES if r.error_type == error_type), None)


def _clip(line: str) -> str:
    line = line.strip()
    if len(line) > MAX_EVIDENCE_LINE_CHARS:
        return line[: MAX_EVIDENCE_LINE_CHARS - 3] + "..."
    return line


def _confidence(score: int, has_strong: bool) -> str:
    if has_strong or score >= HIGH_SCORE_WITHOUT_STRONG:
        return "High"
    if score >= MEDIUM_SCORE:
        return "Medium"
    return "Low"


def _select_evidence(lines: list[str], compiled: _CompiledRule) -> list[str]:
    """Pick matching lines, preferring strong-signal lines, in original log order."""
    strong_idx: list[int] = []
    weak_idx: list[int] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        hits = [s for s, rx in compiled.signals if rx.search(line)]
        if any(s.strong for s in hits):
            strong_idx.append(i)
        elif hits:
            weak_idx.append(i)
    chosen = sorted((strong_idx + weak_idx)[:MAX_EVIDENCE_LINES])
    return [_clip(lines[i]) for i in chosen]


def _score_rule(text: str, lines: list[str], compiled: _CompiledRule) -> _Match | None:
    matched = [s for s, rx in compiled.signals if rx.search(text)]
    if not matched:
        return None
    context_hits = sum(1 for rx in compiled.context if rx.search(text))
    score = sum(s.weight for s in matched) + min(context_hits * CONTEXT_WEIGHT, MAX_CONTEXT_BONUS)
    return _Match(
        rule=compiled.rule,
        score=score,
        has_strong=any(s.strong for s in matched),
        signals=matched,
        evidence=_select_evidence(lines, compiled),
    )


def analyze_logs(text: str) -> AnalysisResult:
    """Analyze log text and return the most likely error category.

    Raises ValueError if the input is empty or whitespace only.
    """
    if text is None or not text.strip():
        raise ValueError("No log text provided.")

    truncated = len(text) > MAX_LOG_CHARS
    if truncated:
        text = text[:MAX_LOG_CHARS]

    lines = text.splitlines()
    analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    matches = [m for c in _COMPILED_RULES if (m := _score_rule(text, lines, c))]

    if not matches:
        return AnalysisResult(
            error_type=UNKNOWN_ERROR_TYPE,
            title="Unrecognized error",
            severity="Unknown",
            confidence="None",
            causes=[],
            steps=list(UNKNOWN_STEPS),
            truncated_input=truncated,
            analyzed_at=analyzed_at,
        )

    # Highest score wins; ties prefer a strong signal, then higher severity.
    # sorted() is stable, so remaining ties keep rule order.
    matches.sort(
        key=lambda m: (m.score, m.has_strong, SEVERITY_ORDER.get(m.rule.severity, 0)),
        reverse=True,
    )
    best = matches[0]

    return AnalysisResult(
        error_type=best.rule.error_type,
        title=best.rule.title,
        severity=best.rule.severity,
        confidence=_confidence(best.score, best.has_strong),
        evidence=best.evidence,
        matched_signals=[s.label for s in best.signals],
        causes=list(best.rule.causes),
        steps=list(best.rule.steps),
        other_detected=[m.rule.title for m in matches[1:]],
        score=best.score,
        truncated_input=truncated,
        analyzed_at=analyzed_at,
    )


def _fence(content: str) -> str:
    """Wrap content in a code fence longer than any backtick run inside it."""
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{content}\n{fence}"


TENTATIVE_NOTE = (
    "Only generic signals matched, so this classification is tentative. "
    "Add more log context (the full error and surrounding lines) to confirm it."
)


def generate_markdown_report(
    result: AnalysisResult,
    ai_explanation: str | None = None,
    ai_model_id: str | None = None,
    ai_warnings: list[str] | None = None,
) -> str:
    """Build a Markdown incident report from an analysis result.

    ai_explanation is optional text from an AI model, included in its own
    clearly labeled section when provided.
    """
    out: list[str] = [
        "# VoiceOps AI Incident Report",
        "",
        f"- **Generated:** {result.analyzed_at}",
        f"- **Detected error type:** {result.title} (`{result.error_type}`)",
        f"- **Severity (rule-based estimate):** {result.severity}",
        f"- **Confidence:** {result.confidence}",
    ]
    if result.matched_signals:
        out.append(f"- **Matched signals:** {'; '.join(result.matched_signals)}")
    if result.other_detected:
        out.append(f"- **Also detected:** {', '.join(result.other_detected)}")
    if result.truncated_input:
        out.append(f"- **Note:** Input was truncated to the first {MAX_LOG_CHARS:,} characters.")
    out.append("")
    if result.is_tentative:
        out += [f"> **Tentative:** {TENTATIVE_NOTE}", ""]

    out += ["## Matching evidence", ""]
    if result.evidence:
        out += [_fence("\n".join(result.evidence)), ""]
    else:
        out += ["No log lines matched a known error pattern.", ""]

    out += ["## Possible causes", ""]
    if result.causes:
        out += [f"- {c}" for c in result.causes]
    else:
        out.append(
            "The analyzer did not recognize this error, so no root cause is suggested. "
            "Manual investigation is required."
        )
    out.append("")

    heading = "Recommended diagnostic steps" if result.is_known else "General triage steps"
    out += [f"## {heading}", ""]
    out += [f"{i}. {s}" for i, s in enumerate(result.steps, start=1)]
    out.append("")

    if ai_explanation:
        source = f"Amazon Bedrock, model `{ai_model_id}`" if ai_model_id else "Amazon Bedrock"
        out += [
            f"## AI explanation ({source})",
            "",
            "_AI-generated content. Verify before acting._",
            "",
        ]
        if ai_warnings:
            out += [
                "> **Warning:** The AI response mentions commands that can change resources or "
                "run workloads. Do not run them as diagnostic steps: "
                + ", ".join(f"`{w}`" for w in ai_warnings),
                "",
            ]
        out += [ai_explanation.strip(), ""]

    out += [
        "---",
        "",
        "_Generated by VoiceOps AI using local rule-based analysis. Causes are possibilities, "
        "not confirmed root causes. Review every command before running it; VoiceOps AI does "
        "not execute commands or change AWS resources._",
        "",
    ]
    return "\n".join(out)


# Sample incidents use AWS documentation placeholder values (account 123456789012).
SAMPLE_INCIDENTS: dict[str, str] = {
    "Lambda timeout": """\
START RequestId: 8f5c1a2e-3b4d-4e6f-9a1b-2c3d4e5f6a7b Version: $LATEST
2026-10-29T10:15:02.114Z 8f5c1a2e INFO Fetching order details from https://api.example.com/orders/1042
2026-10-29T10:15:31.120Z 8f5c1a2e Task timed out after 30.01 seconds
END RequestId: 8f5c1a2e-3b4d-4e6f-9a1b-2c3d4e5f6a7b
REPORT RequestId: 8f5c1a2e-3b4d-4e6f-9a1b-2c3d4e5f6a7b Duration: 30012.45 ms Billed Duration: 30000 ms Memory Size: 128 MB Max Memory Used: 98 MB Status: timeout
""",
    "IAM access denied": """\
2026-10-29T11:02:44.501Z ERROR Failed to read object reports/2026/october.csv
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:sts::123456789012:assumed-role/report-generator-role/report-fn is not authorized to perform: s3:GetObject on resource: "arn:aws:s3:::example-reports-bucket/reports/2026/october.csv" because no identity-based policy allows the s3:GetObject action
""",
    "API throttling": """\
2026-10-29T12:30:10.002Z WARN Retrying request (attempt 3 of 3)
2026-10-29T12:30:10.418Z ERROR botocore.exceptions.ClientError: An error occurred (ThrottlingException) when calling the PutMetricData operation (reached max retries: 2): Rate exceeded
2026-10-29T12:30:10.419Z ERROR Request failed with HTTP status 400; upstream service returned ThrottlingException
""",
    "Database connection error": """\
2026-10-29T13:45:00.881Z ERROR Unable to acquire database connection
psycopg2.OperationalError: could not connect to server: Connection refused
\tIs the server running on host "orders-db.abc123xyz.us-east-1.rds.amazonaws.com" (10.0.12.34) and accepting
\tTCP/IP connections on port 5432?
2026-10-29T13:45:00.902Z ERROR Health check failed: database unavailable
""",
}
