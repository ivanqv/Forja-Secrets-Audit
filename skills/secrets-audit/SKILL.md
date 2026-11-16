---
name: secrets-audit
description: Audit a project or a live website for exposed secrets and dangerous data exposure — hard-coded API keys, secrets that reach the browser bundle (NEXT_PUBLIC_/VITE_ prefixes, client components), committed .env files, tokens in MCP configs or CLAUDE.md, Supabase service_role keys, open Firebase rules, public source maps, secrets baked into Docker images and keys still alive in git history. Also scans a live site passively (keys in public JS bundles, reachable .env/.git/backups, source maps, CORS, security headers). Every finding is verified before it is reported. Use when the user asks to audit security, check for leaked keys or secrets, review a project before making a repo public or deploying, check what their website exposes, or asks "am I exposing anything?".
---

# Secrets Audit

Find what a project is leaking before someone else does, prove each finding, explain it in plain language and fix it in the right order. Typical cause: code written fast (often with AI help) where keys end up in the frontend, in a committed `.env`, or in a config file nobody thinks of.

`<skill>` below is the folder containing this SKILL.md. Scripts need only Python 3.8+ and git.

## Ground rules

- **Never print a full secret.** Not in chat, reports, commit messages or subagent briefs. Use the redacted form the scanner gives (`sk-ant…xY (108 chars)`). `validate_findings.py` rejects files containing unredacted secrets.
- **Never test whether a key works** by calling the provider's API. Assume any exposed key is compromised.
- **Don't change anything until the user agrees.** Audit first, then propose fixes. Never rewrite git history or force-push without explicit confirmation.
- **A finding is reported only after it has a verdict** (Step 4). The scanner produces *candidates*, not conclusions.
- Answer in the user's language.

## Modes

- **Full audit** — the user asks to audit a project or site. Run every step and produce the report.
- **Quick question** — e.g. "is this key safe in this file?". Answer directly from the code; run the scanner only if it helps. No report files unless asked.

## Step 1 — Set up the run

Keep audit files **outside the project** so they are never committed:

```
~/.forja/secrets-audit/<project-or-host>/run-<N>/
    candidates.json   # scanner output
    findings.json     # verified findings (Step 4)
    SECURITY-AUDIT.md # final report (Step 5)
```

`<N>` is one more than the highest existing run. If a previous run's `findings.json` exists, it is the **baseline** for this run.

Ask (or infer from `git remote -v` and what the user said) whether the repo is **public or private**; if unknown, leave it as `unknown`, which is treated as public.

## Step 2 — Run the scanner

Repository:

```bash
python3 <skill>/scripts/scan.py <project-root> --repo-visibility <public|private|unknown> \
  --json <run>/candidates.json [--baseline <previous-run>/findings.json]
```

It scans tracked files plus untracked-but-not-ignored files (what the next `git add` would publish) and up to 1000 commits of history (`--no-history` on huge repos — say so in the report).

Live website (only the user's own site or one they have permission to test — ask if it's clearly a third party's):

```bash
python3 <skill>/scripts/scan.py https://their-site.com --json <run>/candidates.json [--baseline …]
```

Passive only: ordinary GET requests for what the site already serves (HTML and same-site JS bundles, source maps, ~20 well-known sensitive paths validated by content, a CORS check, headers and cookies). Never attempt logins, change IDs in URLs to read other users' data, or fuzz — that is an authorised pentest, not this skill. Exit code 2 means the site couldn't be analysed (connection error, HTTP 4xx/5xx, anti-bot): say so, never report it as clean. If both the repo and the site are available, run both — the repo shows the cause, the site proves what is actually public.

If `gitleaks` or `trufflehog` are installed (`command -v gitleaks trufflehog`), also run one with redaction on and add any new candidates. Don't install them without asking.

**How severity is computed.** Severity is *impact × exposure*, not a checklist: impact is what an attacker gets (`alto` = paid API, payments, database, full repo or cloud access; `medio` = limited or scoped access; `bajo` = little or no direct gain) and exposure is who can reach it (`publico` → `repo` → `pendiente` → `local` → `test`). A private repo lowers repo-level severities by one step. Each candidate shows both, so you can adjust them with evidence.

With a baseline, each candidate is marked `nuevo` or `persiste`, carries the `previous_verdict`, and the run lists what was fixed. Focus effort on new candidates and on persisting ones whose file changed; a previously `rejected` candidate in an unchanged file can keep its verdict (say so in its reason).

## Step 3 — Look for what a regex can't see

Identify the framework first (package.json, config files) — it decides what reaches the browser. Then check by hand and add candidates for anything new:

1. **What ships to the client.** Follow imports from each secret: is the module used by a client component, a page or a browser bundle? Next.js: `'use client'` files and everything they import; `pages/` outside `pages/api/`. Vite/Astro/SvelteKit/Nuxt: `src/` outside server routes, `import.meta.env.VITE_*` / `PUBLIC_*`.
2. **Proxying.** Calls to paid APIs (OpenAI, Anthropic, Stripe…) must be server-side. Flag `fetch` to them from browser code and `dangerouslyAllowBrowser: true`.
3. **Supabase.** `service_role` outside server code; tables without row level security in migrations; storage buckets created `public`.
4. **Firebase.** Rules with `if true` or no auth checks.
5. **Build and deploy.** `productionBrowserSourceMaps`, `build.sourcemap`, `.dockerignore` missing `.env`, `COPY . .` before secrets are excluded, `.git` served from a public folder.
6. **CI.** Workflows that `echo` secrets, upload them as artifacts, or use `pull_request_target` with checkout of PR code.
7. **AI-tool files.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, prompts, `.mcp.json`, `.claude/settings*.json`, n8n exports — versioned *and* sent to the model.
8. **Logs and errors.** Logging request headers or `process.env`, stack traces or env values in API error responses.

## Step 4 — Verify every candidate

Each candidate ends with exactly one verdict, written into `findings.json` (a copy of `candidates.json` with these fields filled):

| Verdict | Meaning | Required fields |
|---|---|---|
| `confirmed` | Proven from the source: you can point to where the secret lives and how it is reachable | `severity`, `trace` |
| `needs_validation` | One exact fact is still unknown (e.g. "is this AWS key ID paired with a secret anywhere?") | `open_question`; `severity` empty |
| `rejected` | Disproved: fake/test value, public-by-design key, unreachable code… | `rejection_reason` |

**The agent that verifies a finding is never the one that found it.** For every `critical`/`high` candidate (and any you're unsure about), hand it to a **fresh subagent** whose job is to *disprove* it, using the brief in [`references/VERIFICATION.md`](references/VERIFICATION.md). Group candidates by file to keep it to a handful of subagents; run them in parallel when the environment allows. Medium and lower candidates can be verified by you directly. If subagents aren't available, do a separate, explicit "try to disprove" pass per candidate and note in the report that verification was not independent.

Rules for the verdict:

- **Severity needs impact.** Confirm the impact × exposure the scanner proposed, or change it with a reason in `trace`.
- **Defense in depth is not a vulnerability.** If one layer already blocks the attack (e.g. the key is server-only and the missing piece is a `.dockerignore`), confirm it with `severity: "info"` and add the tag `hardening`.
- **Public-by-design values are rejected**, not downgraded: Stripe publishable keys, Supabase anon keys, Firebase web config, reCAPTCHA site keys, Google Maps browser keys restricted by referrer.

Then validate — fix and re-run until it passes:

```bash
python3 <skill>/scripts/validate_findings.py <run>/findings.json
```

## Step 5 — Report

```bash
python3 <skill>/scripts/render_report.py <run>/findings.json --out <run>/SECURITY-AUDIT.md
```

In chat, give the verdict in two lines (is anything critical exposed right now?), the rotation checklist and the top fixes; point to the report file for the rest. Offer to copy the report into the project (it only contains redacted values).

For every exposed secret the fix order is always:

1. **Rotate** the key in the provider's dashboard. Removing it from code does not un-leak it.
2. **Move** it to a server-only environment variable; if the browser needs the feature, add a server endpoint that calls the provider.
3. **Clean** the repo: `git rm --cached` for committed env files, `.gitignore`/`.dockerignore` entries, and — only after rotating, and only if the repo is or will be public — history cleanup with `git filter-repo` (it rewrites history: force-push and re-clones needed).
4. **Prevent**: GitHub push protection / secret scanning, the Forja Secrets Guard hook, a `.env.example` with placeholders.

## Step 6 — Fix (only after a yes)

Make the code-level changes, then run a new audit with the run you just finished as baseline and show what moved to "fixed". Rotation in the provider dashboards is the user's to do — list each key (redacted) still pending.
