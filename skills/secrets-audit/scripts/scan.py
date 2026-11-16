#!/usr/bin/env python3
"""Forja Secrets Audit — scanner.

Finds secrets and dangerous exposure in a project: hard-coded keys, secrets that
reach the browser bundle, committed .env files, AI-tool configs with tokens,
open Firebase rules, public source maps, Docker leaks and secrets that live on
in git history.

Usage:
    python3 scan.py [PATH] [--md report.md] [--json report.json] [--no-history] [--max-commits N]
    python3 scan.py https://your-site.com [--md report.md]      (passive live-site mode, see url_scan.py)

Exit code: 0 = nothing critical/high, 1 = critical or high findings, 2 = error.
Standard library only. Secrets are always redacted in the output.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import (  # noqa: E402
    PUBLIC_BY_DESIGN_RE, PUBLIC_ENV_PREFIXES, SENSITIVE_NAME_RE, SEVERITY_ORDER,
    is_placeholder, public_env_exposures, redact, scan_text,
)
from triage import (  # noqa: E402
    EXPOSURE_LABEL, IMPACT_FROM_BASE, baseline_markdown, compare, finalize, load_baseline,
)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pnpm-store", ".turbo",
             ".cache", "vendor", ".idea", ".vscode-test", "coverage", ".terraform"}
SKIP_FILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "composer.lock",
              "poetry.lock", "Cargo.lock", "go.sum"}
MAX_BYTES = 1_500_000
ENV_FILE_RE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_TEMPLATE_RE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)
CLIENT_DIR_RE = re.compile(r"(^|/)(public|static|www|assets|dist|build|out|\.next/static|\.output/public)/")
PUBLIC_MAP_RE = re.compile(r"(^|/)(public|static|www|\.next/static|\.output/public|build/static)/")
SERVER_HINT_RE = re.compile(r"(^|/)(api|server|functions|supabase/functions|backend|scripts|migrations|lib/server)/|\.server\.[jt]sx?$|route\.[jt]s$|middleware\.[jt]s$")
CLIENT_EXT = (".vue", ".svelte", ".astro")
JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro")
TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|__mocks__|mocks?|testdata|examples?)/|\.(test|spec)\.[jt]sx?$")
AI_CONTEXT_FILES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md"}
MCP_CONFIG_RE = re.compile(r"(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|\.claude/settings(\.local)?\.json|\.cursor/mcp\.json|\.vscode/mcp\.json)$")
PUBLIC_ENV_USE_RE = re.compile(r"\b(?:process\.env|import\.meta\.env)\.(" + "|".join(p.rstrip("_") + r"_[A-Z0-9_]+" for p in PUBLIC_ENV_PREFIXES) + r")")


HEAD_EVIDENCE: set[str] = set()  # redacted values present in the current tree

DETAIL = {
    "supabase-service-role": "La service_role ignora todas las políticas RLS: quien la tenga puede leer y escribir toda la base de datos.",
    "private-key": "Una clave privada da acceso directo a servidores, firmas o certificados.",
    "db-url-password": "Con esta URL cualquiera puede conectarse a la base de datos si el puerto es accesible.",
}

@dataclass
class Finding:
    severity: str
    rule: str
    title: str
    file: str
    line: int | None = None
    evidence: str = ""
    detail: str = ""
    fix: str = ""
    tags: list[str] = field(default_factory=list)
    impact: str = ""          # alto | medio | bajo (secret-type findings)
    exposure: str = ""        # publico | repo | pendiente | local | test
    id: str = ""              # stable fingerprint across runs
    verdict: str = "candidate"  # set by the verification step: confirmed | needs_validation | rejected
    status: str = ""          # vs baseline: nuevo | persiste
    previous_verdict: str = ""


FIX = {
    "secret": "Rota la clave en el panel del proveedor (asúmela comprometida), muévela a una variable de entorno de servidor y elimina el valor del código.",
    "client": "Esta clave llega al navegador: cualquiera puede leerla. Rótala y mueve la llamada a un endpoint de servidor (API route / server action / edge function) que use la clave sin exponerla.",
    "env": "Saca el archivo del repositorio (git rm --cached), añade '.env*' (excepto .env.example) a .gitignore y rota todos los valores que contenía.",
    "history": "Aunque ya no esté en el código, sigue en el historial de git. Rótala primero; después, si el repo es o será público, limpia el historial con git filter-repo o BFG.",
    "mcp": "Los tokens de servidores MCP no deben ir en archivos versionados: usa variables de entorno (\"env\": {\"TOKEN\": \"${TOKEN}\"}) o un archivo local ignorado, y rota el token.",
    "ai": "Los archivos de contexto de IA (CLAUDE.md, .cursorrules…) se versionan y se envían al modelo: no pongas credenciales ahí. Rótala y referencia la variable de entorno por su nombre.",
}


def run(cmd: list[str], cwd: Path) -> str | None:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180,
                              encoding="utf-8", errors="replace").stdout
    except Exception:
        return None


def is_git_repo(root: Path) -> bool:
    out = run(["git", "rev-parse", "--is-inside-work-tree"], root)
    return bool(out and out.strip() == "true")


def list_files(root: Path, git: bool) -> tuple[list[str], set[str]]:
    """Return (files_to_scan, tracked_files). In git repos: tracked + untracked-not-ignored."""
    if git:
        tracked = set((run(["git", "ls-files", "-z"], root) or "").split("\0")) - {""}
        untracked = set((run(["git", "ls-files", "-z", "-o", "--exclude-standard"], root) or "").split("\0")) - {""}
        files = sorted(tracked | untracked)
        # Also look at env files that exist but are ignored, only to report they are fine/not.
        return files, tracked
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            files.append(str(Path(dirpath, f).relative_to(root)).replace(os.sep, "/"))
    return sorted(files), set()


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def is_client_side(rel: str, text: str) -> bool:
    if SERVER_HINT_RE.search(rel):
        return False
    if CLIENT_DIR_RE.search(rel) or rel.endswith(CLIENT_EXT):
        return True
    head = text[:400]
    return "'use client'" in head or '"use client"' in head


def scan_files(root: Path, files: list[str], tracked: set[str], git: bool) -> list[Finding]:
    out: list[Finding] = []
    for rel in files:
        parts = rel.split("/")
        if any(p in SKIP_DIRS for p in parts[:-1]) or parts[-1] in SKIP_FILES:
            continue
        path = root / rel
        if not path.is_file():
            continue

        if rel.endswith(".map") and PUBLIC_MAP_RE.search(rel):
            out.append(Finding("medium", "public-sourcemap", "Source map publicado", rel,
                               detail="Los source maps en carpetas públicas permiten reconstruir tu código fuente original, incluidos comentarios y rutas internas.",
                               fix="Desactiva los source maps en producción (p. ej. productionBrowserSourceMaps: false, build.sourcemap: false) o súbelos solo a tu herramienta de errores."))
            continue

        text = read_text(path)
        if text is None:
            continue
        name = parts[-1]
        is_env = bool(ENV_FILE_RE.search(rel)) and not ENV_TEMPLATE_RE.search(rel)
        client = is_client_side(rel, text)
        is_mcp = bool(MCP_CONFIG_RE.search(rel))
        is_ai_ctx = name in AI_CONTEXT_FILES or rel.endswith(".github/copilot-instructions.md")

        # 1) .env files that are committed or about to be
        if is_env and git:
            state = "versionado" if rel in tracked else "sin ignorar (entrará en el próximo git add)"
            real_values = [ln for ln in text.splitlines()
                           if "=" in ln and not ln.strip().startswith("#")
                           and (v := ln.split("=", 1)[1].strip().strip("'\"")) and not is_placeholder(v)]
            if real_values:
                out.append(Finding("critical", "env-committed",
                                   f"Archivo {name} {state}", rel,
                                   detail=f"Contiene {len(real_values)} valores reales.", fix=FIX["env"], tags=["env"],
                                   impact="alto", exposure="repo" if rel in tracked else "pendiente"))

        # 2) Sensitive values behind public env prefixes (end up in the browser bundle)
        if is_env or ENV_TEMPLATE_RE.search(rel):
            for ln, var, val in public_env_exposures(text):
                HEAD_EVIDENCE.add(val)
                out.append(Finding("critical", "public-env-secret", f"Secreto con prefijo público: {var}", rel, ln, val,
                                   detail="Las variables con prefijos como NEXT_PUBLIC_, VITE_ o PUBLIC_ se incrustan en el JavaScript que descarga el navegador.",
                                   fix=FIX["client"], tags=["client"], impact="alto", exposure="publico"))

        # 3) Code that reads a sensitive public env var
        if not is_env and rel.endswith(JS_EXT):
            for ln, line in enumerate(text.splitlines(), 1):
                for m in PUBLIC_ENV_USE_RE.finditer(line):
                    var = m.group(1)
                    bare = var
                    for p in PUBLIC_ENV_PREFIXES:
                        if var.startswith(p):
                            bare = var[len(p):]
                    if SENSITIVE_NAME_RE.search(bare) and not PUBLIC_BY_DESIGN_RE.search(bare):
                        out.append(Finding("high", "public-env-usage", f"El código usa {var} (sensible y público)", rel, ln,
                                           detail="El nombre indica una credencial privada, pero el prefijo la expone al cliente.",
                                           fix=FIX["client"], tags=["client"], impact="medio", exposure="publico"))

        # 4) Hard-coded secrets
        for rid, rname, sev, ln, ev in scan_text(text, generic=not name.endswith((".md", ".lock")) or is_ai_ctx):
            HEAD_EVIDENCE.add(ev)
            tags, fix, detail = [], FIX["secret"], DETAIL.get(rid, "")
            if client:
                tags, fix = ["client"], FIX["client"]
                detail = "El archivo parece ejecutarse en el navegador, así que la clave es pública."
            if is_mcp:
                tags, fix = tags + ["mcp"], FIX["mcp"]
                detail = "Configuración de servidor MCP versionada con el token en claro."
            if is_ai_ctx:
                tags, fix = tags + ["ai-context"], FIX["ai"]
                detail = "Credencial escrita en un archivo de contexto para asistentes de IA."
            if is_env and git:
                continue  # already reported as a whole file
            if client:
                exposure = "publico"
            elif is_env and not git:
                exposure = "local"
                detail = "Archivo .env local (no es un repo git, no se puede saber si se publica)."
            elif TEST_PATH_RE.search(rel):
                exposure = "test"
                detail = (detail + " " if detail else "") + "Está en una carpeta de tests/ejemplos: revisa si es un dato de prueba falso."
            elif git and rel not in tracked:
                exposure = "pendiente"
            else:
                exposure = "repo"
            out.append(Finding(sev, rid, rname, rel, ln, ev, detail, fix, tags,
                               impact=IMPACT_FROM_BASE[sev], exposure=exposure))

        # 5) Docker: secrets baked into images
        file_evidence = {f.evidence for f in out if f.file == rel}
        if name.startswith("Dockerfile") or name.endswith(".dockerfile"):
            for ln, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                m = re.match(r"(?i)(ENV|ARG)\s+([A-Z0-9_]+)[ =]+(\S+)", s)
                if m and redact(m.group(3)) in file_evidence:
                    continue  # already reported by a provider rule
                if m and SENSITIVE_NAME_RE.search(m.group(2)) and not PUBLIC_BY_DESIGN_RE.search(m.group(2)) \
                        and not is_placeholder(m.group(3)) and len(m.group(3)) >= 8:
                    out.append(Finding("high", "docker-secret", f"Secreto en {m.group(1).upper()} {m.group(2)}", rel, ln, redact(m.group(3)),
                                       detail="ENV/ARG quedan grabados en las capas de la imagen y se ven con 'docker history'.",
                                       fix="Pásalo en tiempo de ejecución (variables del orquestador, docker secrets o --env-file) o usa BuildKit secrets (RUN --mount=type=secret).",
                                       impact="medio", exposure="repo" if rel in tracked or not git else "pendiente"))
                if re.match(r"(?i)(COPY|ADD)\s+.*\.env(\s|$)", s):
                    out.append(Finding("high", "docker-copy-env", "El Dockerfile copia un .env dentro de la imagen", rel, ln,
                                       fix="No copies .env a la imagen; añade '.env*' a .dockerignore y pasa las variables en runtime."))

        # 6) Firebase rules wide open
        if name in ("firestore.rules", "storage.rules", "database.rules.json"):
            if re.search(r"allow\s+(read|write|read,\s*write)\s*(:\s*if\s+true)?\s*;", text) or re.search(r'"\.(read|write)"\s*:\s*true', text):
                out.append(Finding("high", "firebase-open-rules", "Reglas de Firebase abiertas", rel,
                                   detail="Cualquiera con la config pública del proyecto puede leer o escribir datos.",
                                   fix="Restringe por request.auth y por propietario del documento; prueba las reglas con el emulador."))

        # 7) n8n credential exports (decrypted)
        if name.endswith(".json") and '"data"' in text and '"type"' in text and re.search(r'"type"\s*:\s*"[a-zA-Z]+(Api|OAuth2Api|Auth)"', text):
            out.append(Finding("high", "n8n-credentials", "Posible exportación de credenciales de n8n", rel,
                               detail="Las exportaciones de credenciales de n8n (--decrypted) contienen los secretos en claro.",
                               fix="Elimina el archivo del repo, rota esas credenciales y exporta solo workflows (sin credenciales)."))

    # 8) .gitignore coverage
    if git:
        rc = subprocess.run(["git", "check-ignore", "-q", "--no-index", ".env"], cwd=root).returncode
        if rc != 0:
            out.append(Finding("medium", "gitignore-env", ".env no está en .gitignore", ".gitignore",
                               fix="Añade a .gitignore: `.env`, `.env.*` y `!.env.example`."))
        if (root / "Dockerfile").exists() and not (root / ".dockerignore").exists():
            out.append(Finding("low", "no-dockerignore", "Hay Dockerfile pero no .dockerignore", "Dockerfile",
                               fix="Crea .dockerignore con al menos: .env*, .git, node_modules."))
    return out


def scan_history(root: Path, max_commits: int) -> list[Finding]:
    log = run(["git", "log", "--all", "-p", "--no-color", "-U0", f"--max-count={max_commits}",
               "--format=@@COMMIT %h %ad", "--date=short"], root)
    if not log:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    commit, file = "", ""
    for line in log.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line[9:]
            continue
        if line.startswith("+++ b/"):
            file = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for rid, rname, sev, _, ev in scan_text(line[1:], generic=False):
            key = f"{rid}:{ev}"
            if key in seen or ev in HEAD_EVIDENCE:
                continue
            seen.add(key)
            out.append(Finding(sev, f"history-{rid}", f"{rname} en el historial de git", file, None, ev,
                               detail=f"Introducido en el commit {commit}. Ya no está en el código actual, pero cualquiera con acceso al repo puede recuperarlo.",
                               fix=FIX["history"], tags=["history"], impact=IMPACT_FROM_BASE[sev], exposure="repo"))
    return out


def to_markdown(root: Path, findings: list[Finding], git: bool, history: bool, diff: dict | None = None) -> str:
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    lines = [f"# Forja Secrets Audit — {root.name}", "",
             f"- Repositorio git: {'sí' if git else 'no'} · Historial analizado: {'sí' if history else 'no'}",
             "- Resumen: " + " · ".join(f"{icon[s]} {s}: {n}" for s, n in counts.items() if n) if findings else "- Sin hallazgos.",
             ""] + baseline_markdown(diff)
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        lines += [f"## {icon[sev]} {sev.upper()} ({len(group)})", ""]
        for f in group:
            loc = f"`{f.file}`" + (f":{f.line}" if f.line else "")
            badge = " 🆕" if f.status == "nuevo" else ""
            lines.append(f"### {f.title}{badge}")
            lines.append(f"- **Dónde:** {loc}" + (f" · **Valor:** `{f.evidence}`" if f.evidence else "") + f" · **ID:** `{f.id}`")
            if f.impact and f.exposure:
                lines.append(f"- **Impacto:** {f.impact} · **Exposición:** {EXPOSURE_LABEL[f.exposure]}")
            if f.detail:
                lines.append(f"- **Por qué importa:** {f.detail}")
            if f.fix:
                lines.append(f"- **Cómo arreglarlo:** {f.fix}")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) > 1 and re.match(r"https?://", sys.argv[1]):
        from url_scan import main as url_main  # live website mode
        return url_main(sys.argv[1:])
    ap = argparse.ArgumentParser(description="Forja Secrets Audit scanner")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--md", help="write Markdown report to this file")
    ap.add_argument("--json", help="write JSON findings to this file")
    ap.add_argument("--no-history", action="store_true", help="skip git history scan")
    ap.add_argument("--max-commits", type=int, default=1000)
    ap.add_argument("--repo-visibility", choices=["public", "private", "unknown"], default="unknown",
                    help="unknown is treated as public (conservative)")
    ap.add_argument("--baseline", help="JSON from a previous run: marks findings as new/persisting and lists what was fixed")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2
    git = is_git_repo(root)
    if git:
        top = run(["git", "rev-parse", "--show-toplevel"], root)
        if top and top.strip():
            root = Path(top.strip())
    files, tracked = list_files(root, git)
    findings = scan_files(root, files, tracked, git)

    history = git and not args.no_history
    if history:
        findings += scan_history(root, args.max_commits)

    # dedupe + sort
    uniq = {(f.rule, f.file, f.line, f.evidence): f for f in findings}
    findings = finalize(list(uniq.values()), args.repo_visibility)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line or 0))
    diff = compare(findings, load_baseline(args.baseline),
                   skip=None if history else (lambda d: str(d.get("rule", "")).startswith("history-"))) if args.baseline and Path(args.baseline).exists() else None

    md = to_markdown(root, findings, git, history, diff)
    if args.md:
        Path(args.md).write_text(md, encoding="utf-8")
    if args.json:
        meta = {"mode": "repo", "target": str(root), "git": git, "history": history,
                "repo_visibility": args.repo_visibility, "baseline": diff}
        Path(args.json).write_text(json.dumps({"meta": meta, "findings": [asdict(f) for f in findings]},
                                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(md)
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
