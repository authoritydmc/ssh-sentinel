# AI operator start prompt

Paste the block below into any coding AI. The AI does the rest.

```text
Set up SSH Sentinel from https://github.com/authoritydmc/ssh-sentinel (branch master).
Obey AGENTS.md and docs/ARCHITECTURE.md. Work in simplified English.
Steps:
1. Clone the repo (or pull latest) and run scripts/install-hooks.sh.
2. Read .env.example and create .env. Ask me only for HOST_ID,
   AUTH_MODE + credentials, and agent join values if I want a fleet.
3. Deploy with docker compose for my case: single host, fleet central,
   fleet agent (ROLE=agent), or demo profile.
4. Verify: /healthz returns ok, /api/auth shows the expected mode,
   CI checks from AGENTS.md pass.
5. Report: URLs, login used, versions, and what to do next.
Never commit secrets. Never skip hooks. Confirm Docker Hub/GHCR tags
before you claim a release is done.
```

## What the installer does

`scripts/ai-install.sh` prepares the machine and the repo:

1. Checks for `git`, `docker`, `python3` (warns, does not install).
2. Clones the repo (or updates it if present).
3. Runs `scripts/install-hooks.sh` (commit-msg, pre-commit, pre-push).
4. Creates `.env` from `.env.example` when missing.
5. Prints the prompt above so the AI continues with setup.

One-line bootstrap (review it first, then run):

```bash
curl -fsSL https://raw.githubusercontent.com/authoritydmc/ssh-sentinel/master/scripts/ai-install.sh | bash
```
