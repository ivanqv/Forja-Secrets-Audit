#!/usr/bin/env python3
"""Validate a verified findings file before reporting.

Every finding must carry a final verdict:
  confirmed         -> needs severity + trace (how it was proven: file, import chain, URL that served it…)
  needs_validation  -> needs open_question (the exact fact still unknown); severity must be empty
  rejected          -> needs rejection_reason
No finding may be left as "candidate", and no string anywhere may contain an unredacted secret.

Usage: python3 validate_findings.py findings.json
Exit 0 = valid, 1 = invalid (errors printed), 2 = unreadable file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import SEVERITY_ORDER, scan_text  # noqa: E402

VERDICTS = {"confirmed", "needs_validation", "rejected"}


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)


def validate(data) -> list[str]:
    errors: list[str] = []
    findings = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(findings, list):
        return ["El archivo debe ser una lista de hallazgos o un objeto con la clave 'findings'."]
    seen = set()
    for i, f in enumerate(findings):
        where = f"#{i} {f.get('id', '?')} ({f.get('title', '')[:50]})"
        fid = f.get("id")
        if not fid:
            errors.append(f"{where}: falta 'id'.")
        elif fid in seen:
            errors.append(f"{where}: 'id' duplicado.")
        seen.add(fid)
        for k in ("rule", "title", "file"):
            if not f.get(k):
                errors.append(f"{where}: falta '{k}'.")
        v = f.get("verdict")
        if v not in VERDICTS:
            errors.append(f"{where}: verdict '{v}' no válido; usa confirmed, needs_validation o rejected.")
            continue
        sev = f.get("severity") or ""
        if v == "confirmed":
            if sev not in SEVERITY_ORDER:
                errors.append(f"{where}: un hallazgo confirmado necesita severity ({', '.join(SEVERITY_ORDER)}).")
            if not str(f.get("trace", "")).strip():
                errors.append(f"{where}: un hallazgo confirmado necesita 'trace' (cómo se ha comprobado).")
        elif v == "needs_validation":
            if sev:
                errors.append(f"{where}: needs_validation no lleva severity (déjalo vacío).")
            if not str(f.get("open_question", "")).strip():
                errors.append(f"{where}: needs_validation necesita 'open_question' (qué dato falta exactamente).")
        elif v == "rejected" and not str(f.get("rejection_reason", "")).strip():
            errors.append(f"{where}: un rechazo necesita 'rejection_reason'.")
    for s in strings(data):
        hits = list(scan_text(s, generic=False))
        if hits:
            errors.append(f"Hay un secreto sin redactar en el archivo ({hits[0][1]}). Usa siempre la forma redactada.")
            break
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    try:
        data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"No se puede leer {sys.argv[1]}: {e}", file=sys.stderr)
        return 2
    errors = validate(data)
    if errors:
        print(f"❌ {len(errors)} errores:")
        for e in errors:
            print(f"  - {e}")
        return 1
    findings = data["findings"] if isinstance(data, dict) else data
    counts = {v: sum(1 for f in findings if f["verdict"] == v) for v in sorted(VERDICTS)}
    print("✅ Válido · " + " · ".join(f"{k}: {n}" for k, n in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
