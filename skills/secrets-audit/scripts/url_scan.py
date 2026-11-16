#!/usr/bin/env python3
"""Forja Secrets Audit — passive scan of a live website.

Looks only at what the site already serves to anyone, with ordinary GET requests:
  * API keys and secrets inside the public JavaScript bundles and inline scripts
  * Public source maps
  * Sensitive files left reachable: .env, .git, backups, SQL dumps, config copies…
  * CORS that reflects any origin with credentials
  * Missing security headers, version disclosure, insecure cookies

No login attempts, no ID tampering, no fuzzing. Use it on your own sites or with
the owner's permission.

Usage:
    python3 url_scan.py https://example.com [--md report.md] [--json report.json] [--max-scripts 40]
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import SEVERITY_ORDER, scan_text  # noqa: E402
from scan import Finding  # noqa: E402
from triage import EXPOSURE_LABEL, IMPACT_FROM_BASE, baseline_markdown, compare, finalize, load_baseline  # noqa: E402

UA = "ForjaSecretsAudit/0.2 (+https://github.com/ivanqv/Forja-Secrets-Audit)"
MAX_BODY = 6_000_000
TIMEOUT = 12

# path -> (title, severity, validator(body_bytes, text) -> bool, fix)
def _txt(b: bytes) -> str:
    return b[:200_000].decode("utf-8", "replace")


def _not_html(t: str) -> bool:
    return not re.search(r"(?i)<(!doctype|html|head|body)\b", t[:2000])


ENV_OK = lambda b, t: _not_html(t) and len(re.findall(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", t)) >= 2
SENSITIVE_PATHS = [
    ("/.env", "Archivo .env accesible públicamente", "critical", ENV_OK),
    ("/.env.local", "Archivo .env.local accesible públicamente", "critical", ENV_OK),
    ("/.env.production", "Archivo .env.production accesible públicamente", "critical", ENV_OK),
    ("/.git/HEAD", "Repositorio .git expuesto", "critical", lambda b, t: t.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", t or "") is not None),
    ("/.git/config", "Configuración de .git expuesta", "critical", lambda b, t: "[core]" in t and _not_html(t)),
    ("/wp-config.php.bak", "Copia de wp-config.php accesible", "critical", lambda b, t: "DB_PASSWORD" in t),
    ("/wp-config.php~", "Copia de wp-config.php accesible", "critical", lambda b, t: "DB_PASSWORD" in t),
    ("/wp-config.php.save", "Copia de wp-config.php accesible", "critical", lambda b, t: "DB_PASSWORD" in t),
    ("/backup.sql", "Volcado de base de datos accesible", "critical", lambda b, t: bool(re.search(r"(?i)(CREATE TABLE|INSERT INTO)", t))),
    ("/dump.sql", "Volcado de base de datos accesible", "critical", lambda b, t: bool(re.search(r"(?i)(CREATE TABLE|INSERT INTO)", t))),
    ("/database.sql", "Volcado de base de datos accesible", "critical", lambda b, t: bool(re.search(r"(?i)(CREATE TABLE|INSERT INTO)", t))),
    ("/backup.zip", "Copia de seguridad (.zip) accesible", "high", lambda b, t: b[:2] == b"PK"),
    ("/backup.tar.gz", "Copia de seguridad (.tar.gz) accesible", "high", lambda b, t: b[:2] == b"\x1f\x8b"),
    ("/.htpasswd", "Archivo .htpasswd accesible", "high", lambda b, t: bool(re.search(r"(?m)^[^:\s]+:(\$apr1\$|\{SHA\}|\$2[aby]\$)", t))),
    ("/.npmrc", "Archivo .npmrc accesible", "high", lambda b, t: "_authToken" in t or "_auth=" in t),
    ("/.vscode/sftp.json", "Configuración SFTP de VS Code accesible", "high", lambda b, t: '"host"' in t and _not_html(t)),
    ("/docker-compose.yml", "docker-compose.yml accesible", "medium", lambda b, t: "services:" in t and _not_html(t)),
    ("/.DS_Store", "Archivo .DS_Store accesible (lista nombres de archivos)", "low", lambda b, t: b[4:8] == b"Bud1"),
    ("/phpinfo.php", "phpinfo() accesible", "medium", lambda b, t: "phpinfo()" in t or "PHP Version" in t),
    ("/server-status", "Apache server-status accesible", "medium", lambda b, t: "Apache Server Status" in t),
]

SEC_HEADERS = {
    "strict-transport-security": ("low", "Falta Strict-Transport-Security (HSTS)",
                                  "Añade `Strict-Transport-Security: max-age=31536000; includeSubDomains` para forzar HTTPS."),
    "content-security-policy": ("low", "Falta Content-Security-Policy",
                                "Una CSP limita qué scripts pueden ejecutarse y reduce el impacto de un XSS."),
    "x-content-type-options": ("low", "Falta X-Content-Type-Options",
                               "Añade `X-Content-Type-Options: nosniff`."),
}


def _fail(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(2)


class Fetcher:
    def __init__(self, insecure: bool = False):
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.requests = 0

    def get(self, url: str, headers: dict | None = None, limit: int = MAX_BODY):
        """Return (status, headers(dict lower), body bytes, final_url) or (None, {}, b'', url)."""
        self.requests += 1
        req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.ctx) as r:
                body = r.read(limit)
                return r.status, {k.lower(): v for k, v in r.headers.items()}, body, r.geturl()
        except urllib.error.HTTPError as e:
            try:
                body = e.read(20_000)
            except Exception:
                body = b""
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body, url
        except Exception:
            return None, {}, b"", url
        finally:
            time.sleep(0.15)  # be polite


def same_site(url: str, base_host: str) -> bool:
    h = urllib.parse.urlparse(url).hostname or ""
    root = ".".join(base_host.split(".")[-2:])
    return h == base_host or h.endswith("." + root)


def scan_url(url: str, max_scripts: int = 40, insecure: bool = False) -> tuple[list[Finding], dict]:
    if not re.match(r"https?://", url):
        url = "https://" + url
    f = Fetcher(insecure)
    out: list[Finding] = []
    status, hdrs, body, final = f.get(url)
    if status is None:
        _fail(f"No se pudo conectar con {url}")
    if status >= 400:
        _fail(f"{url} respondió HTTP {status}: no se analiza una página de error (¿protección anti-bots o URL incorrecta?)")
    base = f"{urllib.parse.urlparse(final).scheme}://{urllib.parse.urlparse(final).netloc}"
    host = urllib.parse.urlparse(final).hostname or ""
    html = _txt(body)

    # --- headers ---
    if final.startswith("https://"):
        for h, (sev, title, fix) in SEC_HEADERS.items():
            if h not in hdrs:
                out.append(Finding(sev, f"header-{h}", title, final, fix=fix, tags=["headers"]))
    else:
        out.append(Finding("high", "no-https", "La web no usa HTTPS", final,
                           fix="Sirve la web solo por HTTPS y redirige HTTP → HTTPS."))
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        v = hdrs.get(h, "")
        if re.search(r"\d", v):
            out.append(Finding("low", "version-disclosure", f"Cabecera {h} revela versión", final, evidence=v,
                               fix="Oculta la versión del servidor/framework; facilita buscar vulnerabilidades conocidas."))
    for c in [v for k, v in hdrs.items() if k == "set-cookie"]:
        name = c.split("=", 1)[0]
        low = c.lower()
        missing = [a for a in ("secure", "httponly", "samesite") if a not in low]
        if missing and re.search(r"(?i)(sess|auth|token|jwt|sid)", name):
            out.append(Finding("medium", "cookie-flags", f"Cookie de sesión '{name}' sin {', '.join(missing)}", final,
                               fix="Marca las cookies de sesión con Secure, HttpOnly y SameSite=Lax/Strict."))

    # --- CORS ---
    evil = "https://forja-cors-check.example"
    _, ch, _, _ = f.get(final, headers={"Origin": evil}, limit=1000)
    acao, acac = ch.get("access-control-allow-origin", ""), ch.get("access-control-allow-credentials", "").lower()
    if acao == evil and acac == "true":
        out.append(Finding("high", "cors-reflect", "CORS refleja cualquier origen con credenciales", final,
                           detail="Cualquier web puede hacer peticiones autenticadas en nombre del usuario y leer la respuesta.",
                           fix="Usa una lista blanca de orígenes; nunca reflejes el Origin recibido con Allow-Credentials: true."))
    elif acao == evil:
        out.append(Finding("low", "cors-reflect-nocreds", "CORS refleja cualquier origen", final,
                           fix="Revisa que ningún endpoint con datos privados dependa de esta configuración."))

    # --- scripts ---
    srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I)
    srcs += re.findall(r"""<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+\.m?js[^"']*)["']""", html, re.I)
    scripts, seen = [], set()
    for s in srcs:
        u = urllib.parse.urljoin(final, s)
        if u not in seen and same_site(u, host):
            seen.add(u)
            scripts.append(u)
    inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S)

    def check_js(text: str, where: str):
        for rid, rname, sev, ln, ev in scan_text(text, generic=False):
            out.append(Finding(sev, rid, f"{rname} en código público", where, ln, ev,
                               detail="Este código lo descarga cualquier visitante: la clave es pública.",
                               fix="Rota la clave ya y mueve la llamada a un endpoint de servidor. Revisa variables con prefijo público (NEXT_PUBLIC_, VITE_…).",
                               tags=["client", "live"], impact=IMPACT_FROM_BASE[sev], exposure="publico"))

    for i, code in enumerate(inline):
        check_js(code, f"{final} (script inline #{i + 1})")
    scanned = 0
    for u in scripts[:max_scripts]:
        st, _, b, _ = f.get(u)
        if st != 200 or not b:
            continue
        scanned += 1
        js = b.decode("utf-8", "replace")
        check_js(js, u)
        m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)\s*$", js[-500:])
        map_url = urllib.parse.urljoin(u, m.group(1)) if m and not m.group(1).startswith("data:") else u + ".map"
        mst, _, mb, _ = f.get(map_url, limit=4000)
        if mst == 200 and (b'"mappings"' in mb or b'"sources"' in mb) and b'"version"' in mb:
            out.append(Finding("medium", "public-sourcemap", "Source map público", map_url,
                               detail="Permite reconstruir el código fuente original, incluidos comentarios y rutas internas.",
                               fix="Desactiva source maps públicos en producción o protégelos."))

    # --- sensitive paths (with soft-404 baseline) ---
    _, _, base404, _ = f.get(base + "/forja-nonexistent-" + str(int(time.time())), limit=200_000)
    for path, title, sev, ok in SENSITIVE_PATHS:
        st, _, b, _ = f.get(base + path, limit=200_000)
        if st != 200 or not b or b == base404:
            continue
        if ok(b, _txt(b)):
            out.append(Finding(sev, "exposed-file", title, base + path,
                               detail="Cualquiera puede descargarlo ahora mismo.",
                               fix="Bloquéalo en el servidor (o elimínalo del directorio público) y, si contiene credenciales, rótalas todas.",
                               tags=["live"]))

    uniq = {(x.rule, x.file, x.line, x.evidence): x for x in out}
    finalize(list(uniq.values()))
    findings = sorted(uniq.values(), key=lambda x: (SEVERITY_ORDER[x.severity], x.file))
    meta = {"url": final, "scripts_found": len(scripts), "scripts_scanned": scanned,
            "inline_scripts": len(inline), "requests": f.requests}
    return findings, meta


def to_markdown(findings: list[Finding], meta: dict, diff: dict | None = None) -> str:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    counts = {s: sum(1 for x in findings if x.severity == s) for s in SEVERITY_ORDER}
    lines = [f"# Forja Secrets Audit — {meta['url']}", "",
             f"- Modo: web publicada (pasivo) · Scripts analizados: {meta['scripts_scanned']} + {meta['inline_scripts']} inline · Peticiones: {meta['requests']}",
             ("- Resumen: " + " · ".join(f"{icon[s]} {s}: {n}" for s, n in counts.items() if n)) if findings else "- Sin hallazgos.",
             "- No cubre: lógica de la aplicación (IDOR), fuerza bruta en login ni CVE de dependencias.", ""] + baseline_markdown(diff)
    for sev in SEVERITY_ORDER:
        group = [x for x in findings if x.severity == sev]
        if not group:
            continue
        lines += [f"## {icon[sev]} {sev.upper()} ({len(group)})", ""]
        for x in group:
            lines.append(f"### {x.title}" + (" 🆕" if x.status == "nuevo" else ""))
            lines.append(f"- **Dónde:** `{x.file}`" + (f":{x.line}" if x.line else "") + (f" · **Valor:** `{x.evidence}`" if x.evidence else "") + f" · **ID:** `{x.id}`")
            if x.impact and x.exposure:
                lines.append(f"- **Impacto:** {x.impact} · **Exposición:** {EXPOSURE_LABEL[x.exposure]}")
            if x.detail:
                lines.append(f"- **Por qué importa:** {x.detail}")
            if x.fix:
                lines.append(f"- **Cómo arreglarlo:** {x.fix}")
            lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Forja Secrets Audit — passive website scan")
    ap.add_argument("url")
    ap.add_argument("--md")
    ap.add_argument("--json")
    ap.add_argument("--max-scripts", type=int, default=40)
    ap.add_argument("--insecure", action="store_true", help="don't verify TLS certificates")
    ap.add_argument("--baseline", help="JSON from a previous run of this site")
    a = ap.parse_args(argv)
    findings, meta = scan_url(a.url, a.max_scripts, a.insecure)
    diff = compare(findings, load_baseline(a.baseline)) if a.baseline and Path(a.baseline).exists() else None
    meta["mode"], meta["baseline"] = "url", diff
    md = to_markdown(findings, meta, diff)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps({"meta": meta, "findings": [asdict(x) for x in findings]}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(md)
    return 1 if any(x.severity in ("critical", "high") for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
