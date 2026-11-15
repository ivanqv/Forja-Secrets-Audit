---
name: secrets-audit
description: Audit a project for exposed secrets and dangerous data exposure — hard-coded API keys, secrets that reach the browser bundle (NEXT_PUBLIC_/VITE_ prefixes, client components), committed .env files, tokens in MCP configs or CLAUDE.md, Supabase service_role keys, open Firebase rules, public source maps, secrets baked into Docker images and keys still alive in git history. Use when the user asks to audit security, check for leaked keys or secrets, review a project before making a repo public or deploying, or asks "am I exposing anything?".
---

# Secrets Audit

Find what a project is leaking before someone else does, explain it in plain language and fix it in the right order. Typical cause: code written fast (often with AI help) where keys end up in the frontend, in a committed `.env`, or in a config file nobody thinks of.

## Ground rules

- **Never print a full secret.** Not in chat, not in reports, not in commit messages. Use the redacted form the scanner gives (`sk-ant…xY (108 chars)`).
- **Never test whether a key works** by calling the provider's API. Assume any exposed key is compromised.
- **Don't change anything until the user agrees.** Audit first, then propose fixes; apply them only with an explicit yes. Never rewrite git history or force-push without explicit confirmation.
- Answer in the user's language.

## Step 1 — Run the scanner

From the project root (default: the current working directory):

```bash
python3 <this-skill-dir>/scripts/scan.py <project-root> --json /tmp/forja-secrets.json
```

`<this-skill-dir>` is the folder containing this SKILL.md. The script needs only Python 3.8+ and git. It scans tracked files plus untracked-but-not-ignored files (what the next `git add` would publish) and up to 1000 commits of history. Use `--no-history` on huge repos and say so in the report.

If `gitleaks` or `trufflehog` are installed (`command -v gitleaks trufflehog`), also run one of them (`gitleaks detect --no-banner --redact -r /tmp/gitleaks.json` or `trufflehog git file://. --json --no-update`) and merge new findings. Don't install them without asking.

## Step 2 — Review what a regex can't see

Read the scanner output, then check by hand. Identify the framework first (package.json, config files) — it decides what reaches the browser.

1. **What actually ships to the client.** For each secret found in code, follow the imports: is that module used by a client component, a page, or a browser bundle? In Next.js: `'use client'` files and everything they import; anything under `pages/` that isn't `pages/api/`. In Vite/Astro/SvelteKit/Nuxt: files under `src/` outside server routes, plus `import.meta.env.VITE_*` / `PUBLIC_*`. Upgrade or downgrade the scanner's verdict with that evidence.
2. **Proxying.** Calls to OpenAI/Anthropic/Stripe/etc. must happen server-side. Flag any `fetch` to a paid API from browser code, and `dangerouslyAllowBrowser: true`.
3. **Supabase.** `service_role` anywhere outside server code is critical. Check migrations/SQL for tables without `enable row level security`, and storage buckets created as `public`.
4. **Firebase.** Rules files with `if true` or no auth checks.
5. **Deploy and build config.** `productionBrowserSourceMaps`, `build.sourcemap`, `.dockerignore` missing `.env`, `COPY . .` before secrets are excluded, `.git` folder served from a public dir.
6. **CI.** GitHub Actions that `echo` secrets, write them to artifacts, or use `pull_request_target` with checkout of PR code.
7. **AI-tool files.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, prompts, `.mcp.json`, `.claude/settings*.json`, n8n exports: any credential there is versioned and also sent to the model.
8. **Logs and errors.** Code that logs request headers, full env objects (`console.log(process.env)`), or returns stack traces/env in API error responses.
9. **False positives.** Drop findings that are clearly fake (test fixtures, docs examples, public-by-design keys such as Stripe publishable keys, Supabase anon keys, Firebase web config, reCAPTCHA site keys). When unsure, keep it as "revisar" rather than deleting it.

## Step 3 — Report

Lead with a two-line verdict (is anything critical exposed right now?). Then a table: severity · what · where (file:line) · fix. Group by severity:

- **Critical:** a live-looking secret that is public or would be public (browser bundle, committed file in a repo that is or may become public, git history, service_role, private key).
- **High:** secret committed to a private repo, secrets in Docker images or MCP/AI config, open database rules.
- **Medium/Low:** hygiene — missing `.gitignore` entries, public source maps, test-key leaks, missing `.dockerignore`.

For every exposed secret, the fix order is always:

1. **Rotate** the key in the provider's dashboard (revoke the old one). Removing it from code does not un-leak it.
2. **Move** it to a server-only environment variable; if the browser needs the feature, add a server endpoint that calls the provider.
3. **Clean** the repo: `git rm --cached` for committed env files, `.gitignore`/`.dockerignore` entries, and — only after rotating, and only if the repo is or will be public — history cleanup with `git filter-repo` (explain that it rewrites history and needs a force-push and re-clones).
4. **Prevent**: enable GitHub push protection / secret scanning, keep the Forja Secrets Guard hook on, add a `.env.example` with placeholder values.

Offer to save the report as `SECURITY-AUDIT.md` (make sure it only contains redacted values) and to apply the code-level fixes.

## Step 4 — Fix (only after a yes)

Make the changes, then re-run the scanner and show the before/after counts. Remind the user that rotation in the provider dashboards is theirs to do — list each provider and key (redacted) they still need to rotate.
