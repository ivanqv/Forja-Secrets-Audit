"""Shared detection rules for Forja Secrets Audit (scanner + Claude Code hook).

Standard library only. Every rule returns redacted values: full secrets are never
printed, logged or written to reports.
"""
from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    severity: str
    group: int = 0  # regex group holding the secret value


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


# Provider-specific rules: high precision, used everywhere (files, history, hook).
PROVIDER_RULES: list[Rule] = [
    Rule("anthropic-key", "Anthropic API key", _r(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}"), "critical"),
    Rule("openai-key", "OpenAI API key", _r(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{40,}"), "critical"),
    Rule("stripe-live-secret", "Stripe live secret/restricted key", _r(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}"), "critical"),
    Rule("stripe-test-secret", "Stripe test secret key", _r(r"\bsk_test_[0-9A-Za-z]{24,}"), "medium"),
    Rule("aws-access-key", "AWS access key ID", _r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    Rule("aws-secret-key", "AWS secret access key",
         _r(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical", 1),
    Rule("github-token", "GitHub token", _r(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"), "critical"),
    Rule("google-api-key", "Google API key", _r(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    Rule("slack-token", "Slack token", _r(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "high"),
    Rule("slack-webhook", "Slack webhook URL",
         _r(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "high"),
    Rule("discord-webhook", "Discord webhook URL",
         _r(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"), "high"),
    Rule("sendgrid-key", "SendGrid API key", _r(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "high"),
    Rule("huggingface-token", "Hugging Face token", _r(r"\bhf_[A-Za-z0-9]{34,}\b"), "high"),
    Rule("telegram-bot-token", "Telegram bot token", _r(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"), "high"),
    Rule("private-key", "Clave privada",
         _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    Rule("db-url-password", "URL de base de datos con contraseña",
         _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/'\"@]+:([^@\s/'\"]{3,})@[^\s'\"]+"),
         "high", 1),
]

JWT_RE = _r(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

# Generic "something = 'secret'" assignments. Lower precision: entropy + placeholder filtered.
GENERIC_ASSIGN_RE = _r(
    r"(?i)\b([A-Z0-9_\-]*(?:api[_\-]?key|secret|token|passw(?:or)?d|pwd|client[_\-]?secret|access[_\-]?key|private[_\-]?key|auth(?!or))[A-Z0-9_\-]*)"
    r"\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
)
# KEY=value lines in .env-style files (no quotes required)
ENV_LINE_RE = _r(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([^'\"\s#]+)")

PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "PUBLIC_", "REACT_APP_", "EXPO_PUBLIC_",
                       "NUXT_PUBLIC_", "GATSBY_", "VUE_APP_", "STORYBOOK_")
SENSITIVE_NAME_RE = _r(
    r"(?i)(secret|private|service[_]?role|passw|pwd|admin|openai|anthropic|claude|stripe_s|sk_|"
    r"database_url|db_url|mongo|redis|smtp|aws_secret|github_token|webhook|api_?key|token)"
)
# Names that are designed to be public even with "key" in them
PUBLIC_BY_DESIGN_RE = _r(r"(?i)(publishable|anon_?key|public_?key|site_?key|measurement_?id|ga_|gtm_|posthog_key|sentry_dsn|mapbox_token|recaptcha_site)")

NON_SECRET_NAME_RE = _r(r"(?i)(path|url|uri|endpoint|type|name|header|field|prefix|suffix|label|id|env|var|file|dir|length|expir\w*|ttl)$")
NON_SECRET_VALUE_RE = _r(r"^(?:https?:|urn:|file:|\.{0,2}/)|://|^[a-z]+(?:[-_.][a-z]+)+$")

PLACEHOLDER_RE = _r(
    r"(?i)(x{4,}|\*{3,}|your[_\-]?|example|changeme|change_me|placeholder|dummy|sample|redacted|"
    r"<[^>]+>|\$\{|\{\{|\{[A-Za-z_][A-Za-z0-9_]*\}|^[^@\s]+@[^@\s]+\.[a-z]{2,}$|process\.env|import\.meta\.env|os\.environ|getenv|env\(|todo|fixme|insert|replace|"
    r"^(?:test|password|secret|token|none|null|undefined|true|false)$|0{8,}|1234567)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value))


def redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 10:
        return v[:2] + "…" + f" ({len(v)} chars)"
    return f"{v[:6]}…{v[-2:]} ({len(v)} chars)"


def jwt_payload(token: str) -> dict | None:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()).decode("utf-8", "replace"))
    except Exception:
        return None


def scan_text(text: str, *, generic: bool = True, allow_marker: str = "forja-allow"):
    """Yield (rule_id, name, severity, line_no, redacted_value) for each hit in text."""
    seen: set[tuple[str, int, str]] = set()
    for line_no, line in enumerate(text.splitlines(), 1):
        if allow_marker in line:
            continue
        hit_spans: list[tuple[int, int]] = []
        for rule in PROVIDER_RULES:
            for m in rule.pattern.finditer(line):
                val = m.group(rule.group)
                if is_placeholder(val) and rule.id not in ("private-key",):
                    continue
                key = (rule.id, line_no, val)
                if key in seen:
                    continue
                seen.add(key)
                hit_spans.append(m.span())
                yield rule.id, rule.name, rule.severity, line_no, redact(val)
        for m in JWT_RE.finditer(line):
            payload = jwt_payload(m.group(0)) or {}
            role = str(payload.get("role", ""))
            if role == "service_role":
                yield "supabase-service-role", "Supabase service_role key", "critical", line_no, redact(m.group(0))
            elif role == "anon":
                continue  # Supabase anon key is public by design
            elif generic:
                yield "jwt", "JWT escrito en el código", "medium", line_no, redact(m.group(0))
            hit_spans.append(m.span())
        if not generic:
            continue
        for m in GENERIC_ASSIGN_RE.finditer(line):
            name, val = m.group(1), m.group(2)
            if any(s <= m.start(2) < e for s, e in hit_spans):
                continue
            if PUBLIC_BY_DESIGN_RE.search(name) or is_placeholder(val) or re.search(r"(?i)placeholder|example|sample|dummy|fake|mock", name):
                continue
            if NON_SECRET_NAME_RE.search(name) or NON_SECRET_VALUE_RE.search(val):
                continue
            if shannon_entropy(val) < 3.3:
                continue
            yield "generic-secret", f"Secreto escrito en el código en '{name}'", "medium", line_no, redact(val)


def public_env_exposures(text: str):
    """Yield (line_no, var_name, redacted_value) for sensitive values behind public env prefixes."""
    for line_no, line in enumerate(text.splitlines(), 1):
        m = ENV_LINE_RE.match(line)
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        if not name.startswith(PUBLIC_ENV_PREFIXES):
            continue
        bare = name.split("_", 1)[1] if "_" in name else name
        for p in PUBLIC_ENV_PREFIXES:
            if name.startswith(p):
                bare = name[len(p):]
        if PUBLIC_BY_DESIGN_RE.search(bare) or not SENSITIVE_NAME_RE.search(bare):
            continue
        if is_placeholder(val) or len(val) < 8:
            continue
        yield line_no, name, redact(val)
