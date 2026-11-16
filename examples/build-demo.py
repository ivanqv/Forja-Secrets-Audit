#!/usr/bin/env python3
"""Build a deliberately insecure demo project to try Forja Secrets Audit on.

    python3 examples/build-demo.py /tmp/leaky-app
    python3 skills/secrets-audit/scripts/scan.py /tmp/leaky-app

The fake keys are generated at runtime from fragments, so this repository itself
contains no secret-looking strings (and GitHub push protection stays happy).
None of the generated keys are real.
"""
import base64
import json
import random
import string
import subprocess
import sys
from pathlib import Path

rnd = random.Random(42)


def rand(n, alphabet=string.ascii_letters + string.digits):
    return "".join(rnd.choice(alphabet) for _ in range(n))


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


ANTHROPIC = "sk-" + "ant-" + "api03-" + rand(93, string.ascii_letters + string.digits + "-_")
OPENAI = "sk-" + "proj-" + rand(64)
STRIPE = "sk" + "_live_" + rand(32)
GITHUB = "gh" + "p_" + rand(36)
AWS_ID = "AK" + "IA" + rand(16, string.ascii_uppercase + string.digits)
SERVICE_ROLE = ".".join([b64({"alg": "HS256", "typ": "JWT"}),
                         b64({"iss": "supabase", "ref": rand(20).lower(), "role": "service_role", "iat": 1700000000}),
                         rand(43, string.ascii_letters + string.digits + "-_")])
ANON = ".".join([b64({"alg": "HS256", "typ": "JWT"}),
                 b64({"iss": "supabase", "ref": rand(20).lower(), "role": "anon", "iat": 1700000000}),
                 rand(43, string.ascii_letters + string.digits + "-_")])
DB_PASS = rand(20)

FILES = {
    ".gitignore": "node_modules\n.next\n",
    ".env.local": f"NEXT_PUBLIC_OPENAI_API_KEY={OPENAI}\nNEXT_PUBLIC_SUPABASE_ANON_KEY={ANON}\n",
    ".env.example": "OPENAI_API_KEY=your-key-here\nDATABASE_URL=postgres://user:password@localhost:5432/app\n",
    "app/components/Chat.tsx": f"""'use client'
import Anthropic from '@anthropic-ai/sdk'

// TODO: move to server later
const client = new Anthropic({{ apiKey: '{ANTHROPIC}', dangerouslyAllowBrowser: true }})

export function Chat() {{
  const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY
  return null
}}
""",
    "lib/supabase.ts": f"""import {{ createClient }} from '@supabase/supabase-js'
// the anon key didn't work with RLS so we use this one
export const supabase = createClient('https://demo.supabase.co', '{SERVICE_ROLE}')
""",
    "app/api/checkout/route.ts": f"""import Stripe from 'stripe'
const stripe = new Stripe('{STRIPE}')
export async function POST() {{ return Response.json({{ ok: true }}) }}
""",
    "docker-compose.yml": f"""services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: {DB_PASS}
  app:
    build: .
    environment:
      DATABASE_URL: postgres://app:{DB_PASS}@db:5432/app
""",
    "Dockerfile": f"""FROM node:20-alpine
WORKDIR /app
COPY . .
COPY .env .env
ENV STRIPE_SECRET_KEY={STRIPE}
RUN npm ci && npm run build
CMD ["npm", "start"]
""",
    ".mcp.json": json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                                                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB}}}}, indent=2) + "\n",
    "CLAUDE.md": f"""# Project notes for Claude

Deploy with the AWS key {AWS_ID} (ask Iván for the secret).
Never change the checkout flow.
""",
    "firestore.rules": """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
""",
    "public/_next/static/chunks/main.js.map": '{"version":3,"sources":["webpack://app/./app/components/Chat.tsx"]}\n',
}


def main():
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "leaky-app").resolve()
    if target.exists() and any(target.iterdir()):
        sys.exit(f"{target} already exists and is not empty")
    target.mkdir(parents=True, exist_ok=True)
    g = lambda *a: subprocess.run(["git", *a], cwd=target, check=True, capture_output=True)
    g("init", "-q")
    g("config", "user.email", "demo@example.com")
    g("config", "user.name", "Demo")

    # Commit 1: a .env with a real-looking key, later "fixed" by deleting it
    (target / ".env").write_text(f"ANTHROPIC_API_KEY={ANTHROPIC.replace('api03-', 'api03-x')}\n")
    g("add", ".env")
    g("commit", "-qm", "initial setup")
    g("rm", "-q", ".env")
    g("commit", "-qm", "remove .env (oops)")

    for rel, content in FILES.items():
        p = target / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    g("add", "-A")
    g("commit", "-qm", "add app")
    print(f"Demo project ready at {target}")


if __name__ == "__main__":
    main()
