"""Severity, fingerprints and baseline comparison for Forja Secrets Audit.

Severity = impact x exposure (not "the rule says critical"):
  impact   — what an attacker gets with it:   alto | medio | bajo
  exposure — who can reach it today:          publico | repo | pendiente | local | test
    publico   served to any visitor (browser bundle, live URL, public env prefix)
    repo      committed to git (tracked file or history)
    pendiente not committed yet, but not ignored either (next `git add` publishes it)
    local     only on this machine (non-git folder)
    test      in a tests/fixtures/examples path (likely fake data)
Repo exposure depends on repo visibility: public/unknown (assume public) vs private.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

IMPACT_FROM_BASE = {"critical": "alto", "high": "medio", "medium": "bajo", "low": "bajo", "info": "bajo"}

_MATRIX = {
    #            publico     repo(pub)   repo(priv)  pendiente  local     test
    "alto":  {"publico": "critical", "repo": ("critical", "high"), "pendiente": "high", "local": "medium", "test": "low"},
    "medio": {"publico": "high", "repo": ("high", "medium"), "pendiente": "medium", "local": "low", "test": "low"},
    "bajo":  {"publico": "medium", "repo": ("low", "low"), "pendiente": "low", "local": "info", "test": "info"},
}

EXPOSURE_LABEL = {
    "publico": "público (cualquiera puede verlo)",
    "repo": "en el repositorio git",
    "pendiente": "sin ignorar, entraría en el próximo commit",
    "local": "solo en local",
    "test": "carpeta de tests/ejemplos",
}


def severity_for(impact: str, exposure: str, visibility: str = "unknown") -> str:
    cell = _MATRIX[impact][exposure]
    if isinstance(cell, tuple):
        return cell[1] if visibility == "private" else cell[0]
    return cell


def fingerprint(rule: str, file: str, evidence: str, title: str) -> str:
    """Stable id across runs: line numbers are left out on purpose."""
    return hashlib.sha1(f"{rule}|{file}|{evidence or title}".encode()).hexdigest()[:12]


def finalize(findings, visibility: str = "unknown"):
    for f in findings:
        if f.impact and f.exposure:
            f.severity = severity_for(f.impact, f.exposure, visibility)
        f.id = fingerprint(f.rule, f.file, f.evidence, f.title)
    return findings


def load_baseline(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["findings"] if isinstance(data, dict) else data


def compare(findings, baseline: list[dict], skip=None) -> dict:
    """skip(d) -> True for baseline entries this run could not have re-checked (e.g. history when --no-history)."""
    baseline = [d for d in baseline if not (skip and skip(d))]
    prev = {d.get("id"): d for d in baseline if d.get("id")}
    for f in findings:
        old = prev.get(f.id)
        f.status = "persiste" if old else "nuevo"
        if old and old.get("verdict") in ("confirmed", "needs_validation", "rejected"):
            f.previous_verdict = old["verdict"]
    current = {f.id for f in findings}
    fixed = [d for d in baseline if d.get("id") and d["id"] not in current and d.get("verdict") != "rejected"]
    return {
        "fixed": [{"id": d["id"], "title": d.get("title", ""), "file": d.get("file", ""), "severity": d.get("severity", "")} for d in fixed],
        "new": sum(1 for f in findings if f.status == "nuevo"),
        "persisting": sum(1 for f in findings if f.status == "persiste"),
    }


def baseline_markdown(diff: dict | None) -> list[str]:
    if not diff:
        return []
    lines = ["## Desde la auditoría anterior", "",
             f"- ✅ Arreglados: {len(diff['fixed'])} · 🆕 Nuevos: {diff['new']} · ↻ Siguen ahí: {diff['persisting']}", ""]
    for d in diff["fixed"]:
        lines.append(f"  - ✅ {d['title']} (`{d['file']}`)")
    if diff["fixed"]:
        lines.append("")
    return lines
