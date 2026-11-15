# Forja Secrets Audit

**Find and stop leaked secrets in AI-assisted projects — in the repo and on the live site.** A Claude Code plugin with two parts:

- 🔍 **`secrets-audit` skill** — audits a project (or a live URL) and explains, in plain language, what you are exposing and how to fix it in the right order.
- 🔒 **Secrets Guard hook** — blocks Claude *before* it writes an API key into your code, creates a `.env` that git would commit, or commits staged secrets.

Part of the **Forja** toolkit by [IQV Media](https://iqvmedia.com).

## Why

AI tools write code fast, and that's how keys end up in places nobody checks: an OpenAI key behind `NEXT_PUBLIC_`, a Supabase `service_role` in a client file "because RLS didn't work", a GitHub token in `.mcp.json`, an AWS key in `CLAUDE.md`, a `.env` that was deleted but still lives in git history.

Pattern scanners like gitleaks or TruffleHog are great at spotting key formats. This plugin adds **context**:

| Check | What it catches |
|---|---|
| Browser exposure | Secrets behind `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` / `REACT_APP_`…, keys in `'use client'` components, `.vue`/`.svelte`/`.astro` files, public folders |
| Committed env files | `.env*` tracked or about to be added, missing `.gitignore` rules |
| AI-tool configs | Tokens in `.mcp.json`, `claude_desktop_config.json`, `.claude/settings.json`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules` |
| Supabase / Firebase | `service_role` JWTs (anon keys are ignored, they're public by design), open Firestore/RTDB rules |
| Docker | Secrets in `ENV`/`ARG` (baked into image layers), `COPY .env`, missing `.dockerignore` |
| Git history | Keys that were "removed" but are still recoverable from old commits |
| Other leaks | Public source maps, n8n decrypted credential exports, DB URLs with passwords, private keys |

Providers detected: Anthropic, OpenAI, Stripe, AWS, GitHub, Google, Slack, Discord, SendGrid, Hugging Face, Telegram, Supabase, generic JWTs and high-entropy assignments. Secrets are **always redacted** in the output.

## Install (Claude Code)

```
/plugin marketplace add ivanqv/Forja-Secrets-Audit
/plugin install forja-secrets-audit@forja
```

Then just ask: *"audit this project for exposed secrets"* or *"am I leaking anything before I make this repo public?"*

Requirements: Python 3.8+ and git. No dependencies.

## Use the scanner without Claude

```bash
python3 skills/secrets-audit/scripts/scan.py /path/to/project --md report.md --json report.json
```

Exit code `1` when there are critical/high findings, `2` on errors, so it works in CI or as a pre-commit check. Use `--no-history` to skip the git history scan.

## Scan a live website

```bash
python3 skills/secrets-audit/scripts/scan.py https://your-site.com --md web-report.md
```

Or just ask Claude: *"check what my-site.com is exposing"*. **Passive only** — ordinary GET requests for what the site already serves to any visitor:

- API keys and Supabase `service_role` keys inside the public JavaScript bundles and inline scripts
- Public source maps
- Reachable sensitive files: `.env*`, `.git`, SQL dumps, `wp-config.php` copies, backups, `.htpasswd`, `.npmrc`, `docker-compose.yml`, `phpinfo`… (validated by content, so SPA catch-all pages don't cause false positives)
- CORS that reflects any origin with credentials
- Missing security headers, version disclosure, session cookies without `Secure`/`HttpOnly`/`SameSite`

Not covered (by design): login brute force, IDOR/ID tampering, dependency CVEs. Those need an authorised pentest.

> ⚠️ Scan your own sites or sites you have the owner's permission to test.

## The Guard hook

Runs on every `Write`, `Edit`, `MultiEdit` and `Bash` call:

| Claude tries to… | Result |
|---|---|
| Write `const key = 'sk-ant-…'` into a source file | ❌ Blocked — told to use a server env var |
| Write `.env` when git doesn't ignore it | ❌ Blocked — told to fix `.gitignore` first |
| Write `.env` that is ignored | ✅ Allowed (that's where secrets belong) |
| `git add .env` / `git add -A` with an unignored `.env` | ❌ Blocked |
| `git commit` with secrets in the staged diff | ❌ Blocked |
| Anything else | ✅ Allowed |

Need a fake key in a test fixture? Add `forja-allow` in a comment on that line. The hook fails open on unexpected errors so it never breaks your session.

## Try it on the demo

```bash
python3 examples/build-demo.py /tmp/leaky-app
python3 skills/secrets-audit/scripts/scan.py /tmp/leaky-app
```

The demo is a small Next.js-style app with 16 planted problems (see [`examples/sample-report.md`](examples/sample-report.md)). Its fake keys are generated at runtime, so this repository contains no secret-looking strings.

## Important

If a key was ever exposed, **rotate it**. Deleting it from the code — or even from git history — doesn't make it secret again.

## License

MIT © Iván Quintas · [iqvmedia.com](https://iqvmedia.com)
