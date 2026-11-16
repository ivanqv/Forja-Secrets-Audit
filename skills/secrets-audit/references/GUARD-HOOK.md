# Secrets Guard hook (optional, Claude Code)

Blocks, before they happen: writing an API key into a source file, writing a `.env` that git would commit, `git add` of `.env` files, and `git commit` with secrets in the staged diff. Add `forja-allow` in a comment on a line to let a deliberate fake value through.

**If you installed the full plugin** (`/plugin marketplace add ivanqv/Forja-Secrets-Audit`), the hook is already on. Nothing to do.

**If you only have this skill folder**, add the hook to `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project), replacing `<skill>` with the absolute path of this skill folder:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|Bash",
        "hooks": [
          { "type": "command", "command": "python3 \"<skill>/hooks/guard.py\"", "timeout": 30 }
        ]
      }
    ]
  }
}
```

Only edit the settings file with the user's explicit permission, and merge with any existing `hooks` section instead of replacing it. Restart Claude Code (or run `/hooks`) to load it.
