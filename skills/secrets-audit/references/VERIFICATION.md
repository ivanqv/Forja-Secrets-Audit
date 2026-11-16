# Verifier brief

Give each verifier subagent this brief, filled in. Include only the candidate records it must judge (redacted values only) and the project path — not your own reasoning or other findings, so its judgement stays independent.

---

You are verifying candidate security findings in the project at `<project path>` (or the live site `<url>`). Your job is to **try to disprove each candidate**. Only keep it if the evidence survives.

Candidates (JSON, values are redacted):

```json
<the candidate records>
```

For each candidate:

1. Open the file and line. Read enough surrounding code to understand it.
2. Try to disprove it. Typical ways a candidate is wrong:
   - The value is fake, a placeholder, a test fixture or documentation example.
   - The key is public by design (Stripe publishable key, Supabase anon key, Firebase web config, reCAPTCHA site key, referrer-restricted Google Maps key).
   - The code never runs in the browser: it is only imported by server code (API routes, server actions, edge functions, scripts). Follow the imports to check.
   - The file is ignored by git (`git check-ignore -v <file>`) and never committed (`git log --all --oneline -- <file>`).
   - For history findings: the commit is not reachable from any branch or tag that is pushed (`git branch -r --contains <commit>`).
   - For live findings: re-request the URL and check the response is the real file, not an error page or SPA fallback.
3. Decide:
   - `confirmed` — you could not disprove it. Write `trace`: where it lives and how it is reachable (import chain, commit, URL), in one or two sentences. Keep or correct `severity` (impact × exposure) and say why if you change it. If another layer already prevents exploitation, use `severity: "info"` and add the tag `hardening`.
   - `rejected` — you disproved it. Write `rejection_reason`.
   - `needs_validation` — it hinges on one fact you cannot check from here (e.g. whether a key is still active, whether a bucket is public in production). Write that fact as `open_question` and leave `severity` empty.

Rules: never print or copy a full secret value, never call a provider's API to test a key, never modify files or git state.

Return a JSON list with, for each candidate: `id`, `verdict`, `severity`, and `trace` / `rejection_reason` / `open_question`.
