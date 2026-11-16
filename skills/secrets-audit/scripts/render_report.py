#!/usr/bin/env python3
"""Render the final audit report from a validated findings file.

Usage: python3 render_report.py findings.json [--out SECURITY-AUDIT.md]

Refuses to render if the file does not pass validate_findings.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import SEVERITY_ORDER  # noqa: E402
from triage import EXPOSURE_LABEL, baseline_markdown  # noqa: E402
from validate_findings import validate  # noqa: E402

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def render(data: dict) -> str:
    meta = data.get("meta", {}) if isinstance(data, dict) else {}
    findings = data["findings"] if isinstance(data, dict) else data
    conf = [f for f in findings if f["verdict"] == "confirmed"]
    pend = [f for f in findings if f["verdict"] == "needs_validation"]
    rej = [f for f in findings if f["verdict"] == "rejected"]
    target = meta.get("target") or meta.get("url") or "proyecto"
    urgent = [f for f in conf if f["severity"] in ("critical", "high")]

    out = [f"# Auditoría de secretos — {Path(str(target)).name if meta.get('mode') == 'repo' else target}", "",
           f"_Fecha: {date.today().isoformat()} · Modo: {'repositorio' if meta.get('mode') == 'repo' else 'web publicada' if meta.get('mode') == 'url' else '—'}_", ""]
    if urgent:
        out.append(f"**Veredicto:** hay {len(urgent)} problema(s) crítico(s) o alto(s) confirmados. Empieza por rotar las claves de la lista de abajo.")
    elif conf:
        out.append("**Veredicto:** no hay nada crítico confirmado; quedan mejoras de higiene.")
    else:
        out.append("**Veredicto:** no se ha confirmado ninguna exposición.")
    out += ["", f"Confirmados: **{len(conf)}** · Por validar: **{len(pend)}** · Descartados: **{len(rej)}**", ""]
    out += baseline_markdown(meta.get("baseline"))

    rotate = [f for f in conf if f.get("evidence") and f.get("impact") in ("alto", "medio")]
    if rotate:
        out += ["## Claves que debes rotar", "",
                "Rótalas en el panel de cada proveedor **antes** de limpiar el código o el historial.", ""]
        by_key: dict[str, list] = {}
        for f in rotate:
            by_key.setdefault(f["evidence"], []).append(f)
        for ev, group in by_key.items():
            files = ", ".join(sorted({f"`{g['file']}`" for g in group}))
            out.append(f"- [ ] {group[0]['title'].replace(' en el historial de git', '')} · `{ev}` · {files}")
        out.append("")

    if conf:
        out += ["## Hallazgos confirmados", "",
                "| Severidad | Qué | Dónde | Exposición |", "|---|---|---|---|"]
        for f in sorted(conf, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"])):
            loc = f"`{f['file']}`" + (f":{f['line']}" if f.get("line") else "")
            out.append(f"| {ICON[f['severity']]} {f['severity']} | {f['title']} | {loc} | {EXPOSURE_LABEL.get(f.get('exposure', ''), '—')} |")
        out.append("")
        for f in sorted(conf, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"])):
            out.append(f"### {ICON[f['severity']]} {f['title']}" + (" · refuerzo" if "hardening" in f.get("tags", []) else ""))
            out.append(f"- **Dónde:** `{f['file']}`" + (f":{f['line']}" if f.get("line") else "") + (f" · `{f['evidence']}`" if f.get("evidence") else ""))
            if f.get("detail"):
                out.append(f"- **Por qué importa:** {f['detail']}")
            out.append(f"- **Cómo se ha comprobado:** {f['trace']}")
            if f.get("fix"):
                out.append(f"- **Cómo arreglarlo:** {f['fix']}")
            out.append("")

    if pend:
        out += ["## Por validar", "", "Sin severidad hasta resolver la duda concreta de cada uno.", ""]
        for f in pend:
            out.append(f"- **{f['title']}** (`{f['file']}`): {f['open_question']}")
        out.append("")

    if rej:
        out += ["<details><summary>Descartados ({})</summary>".format(len(rej)), ""]
        for f in rej:
            out.append(f"- {f['title']} (`{f['file']}`): {f['rejection_reason']}")
        out += ["", "</details>", ""]

    out += ["---", "_Generado con [Forja Secrets Audit](https://github.com/ivanqv/Forja-Secrets-Audit). Los valores están redactados; nunca se muestran secretos completos._"]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--out")
    a = ap.parse_args()
    data = json.loads(Path(a.findings).read_text(encoding="utf-8"))
    errors = validate(data)
    if errors:
        print("❌ El archivo no pasa la validación; ejecuta validate_findings.py y corrige:", file=sys.stderr)
        for e in errors[:10]:
            print(f"  - {e}", file=sys.stderr)
        return 1
    md = render(data)
    if a.out:
        Path(a.out).write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
