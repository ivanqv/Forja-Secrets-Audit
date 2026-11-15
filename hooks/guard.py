#!/usr/bin/env python3
"""Forja Secrets Guard — Claude Code PreToolUse hook.

Blocks, before they happen:
  * Write / Edit / MultiEdit that put a secret into a file that is not an ignored .env
  * Writing a .env file that git would commit (not in .gitignore)
  * git add of .env files, and git add -A / . when an unignored .env is pending
  * git commit when the staged diff contains secrets or .env files

Exit 0 = allow. Exit 2 = block; the stderr message goes back to Claude so it can fix the approach.
Add the comment `forja-allow` on a line to bypass it deliberately (e.g. test fixtures).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills" / "secrets-audit" / "scripts"))
from rules import scan_text  # noqa: E402

ENV_NAME_RE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_TEMPLATE_RE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)


def git(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=30)


def in_git(cwd: str) -> bool:
    try:
        return git(["rev-parse", "--is-inside-work-tree"], cwd).stdout.strip() == "true"
    except Exception:
        return False


def is_real_env(path: str) -> bool:
    return bool(ENV_NAME_RE.search(path.replace("\\", "/"))) and not ENV_TEMPLATE_RE.search(path)


def ignored(path: str, cwd: str) -> bool:
    return git(["check-ignore", "-q", "--no-index", path], cwd).returncode == 0


def block(msg: str) -> None:
    print(f"🔒 Forja Secrets Guard: {msg}", file=sys.stderr)
    sys.exit(2)


def check_content(content: str, where: str) -> None:
    hits = [h for h in scan_text(content, generic=False)]
    if hits:
        kinds = ", ".join(sorted({h[1] for h in hits}))
        lines = ", ".join(str(h[3]) for h in hits[:5])
        block(f"se ha bloqueado escribir un secreto ({kinds}) en {where} (línea {lines}). "
              "No pongas credenciales en el código: léelas de una variable de entorno de servidor "
              "(p. ej. process.env.X) y guarda el valor solo en un .env ignorado por git. "
              "Si es un dato de prueba falso, añade el comentario 'forja-allow' en esa línea.")


def handle_write(tool: str, ti: dict, cwd: str) -> None:
    path = ti.get("file_path", "") or ""
    if tool == "Write":
        content = ti.get("content", "") or ""
    elif tool == "Edit":
        content = ti.get("new_string", "") or ""
    else:  # MultiEdit
        content = "\n".join(e.get("new_string", "") for e in ti.get("edits", []) or [])

    if is_real_env(path):
        if in_git(cwd) and not ignored(path, cwd):
            block(f"vas a escribir {Path(path).name} pero git no lo ignora, así que acabaría en el repositorio. "
                  "Añade primero '.env', '.env.*' y '!.env.example' a .gitignore.")
        return  # secrets in an ignored .env are the right place
    check_content(content, Path(path).name or "el archivo")


def handle_bash(cmd: str, cwd: str) -> None:
    if not re.search(r"\bgit\b", cmd) or not in_git(cwd):
        return
    # git add <explicit .env>
    for m in re.finditer(r"\bgit\s+add\b([^;&|]*)", cmd):
        args = m.group(1).split()
        explicit_env = [a for a in args if is_real_env(a)]
        if explicit_env:
            block(f"'git add' incluye {', '.join(explicit_env)}. Los .env no se versionan: usa .env.example con valores de ejemplo.")
        if any(a in (".", "-A", "--all", "-u") or a.endswith("/") for a in args):
            status = git(["status", "--porcelain", "--untracked-files=all"], cwd).stdout
            pending = [ln[3:] for ln in status.splitlines() if is_real_env(ln[3:].strip('"'))]
            if pending:
                block(f"'git add' masivo añadiría {', '.join(pending)}. Añádelos a .gitignore antes.")
    # git commit: scan what is staged
    if re.search(r"\bgit\s+commit\b", cmd):
        staged = git(["diff", "--cached", "--name-only"], cwd).stdout.split()
        env_staged = [f for f in staged if is_real_env(f)]
        if env_staged:
            block(f"hay archivos .env preparados para commit: {', '.join(env_staged)}. "
                  "Sácalos con 'git restore --staged <archivo>' y añádelos a .gitignore.")
        diff = git(["diff", "--cached", "-U0", "--no-color"], cwd).stdout
        added = "\n".join(ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
        if added:
            check_content(added, "los cambios preparados para commit")


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # never break Claude Code on malformed input
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}
    cwd = data.get("cwd") or "."
    try:
        if tool in ("Write", "Edit", "MultiEdit"):
            handle_write(tool, ti, cwd)
        elif tool == "Bash":
            handle_bash(ti.get("command", "") or "", cwd)
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)  # fail open on unexpected errors; the audit skill is the safety net
    sys.exit(0)


if __name__ == "__main__":
    main()
