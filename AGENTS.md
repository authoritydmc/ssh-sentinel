# AGENTS.md — rules for automated work in this repo

Read this file before you change code. Obey all rules in it.

## 1. How to communicate (ASD-STE100, 80% rule)

- Use simplified English in all answers, commits, and docs.
- Write short sentences. Limit: 20 words per sentence.
- Give one instruction per sentence in procedures.
- Use the same term for the same thing. See `docs/ARCHITECTURE.md` for terms.
- Do not use idioms, jokes, or marketing language.
- You may break these rules only for exact error text, code, or commands.

## 2. Project map

- `backend/server.py` — API + UI server. Standard library only. No new deps.
- `agent/agent.py` — log shipper. Standard library only.
- `frontend/` — React 19 + Vite + Tailwind. `npm run lint`, `npm run build`.
- `docker/entrypoint.sh` — selects `ROLE=central|agent`.
- `docs/ARCHITECTURE.md` — design truth. Update it when design changes.
- `scripts/release.sh` — the only way to cut a release.

## 3. Hard constraints

- Never commit secrets, tokens, hashes, or real host names.
- Never add backend runtime dependencies. Frontend deps need a reason.
- Keep `AUTH_MODE=local` fail-closed. Do not weaken the gate.
- `/api/abusers` must never expose logins, host names, or private IPs.
- Keep SSDLC order: change code, verify locally, commit, push, watch CI.

## 4. Required checks (in this order)

1. `python3 -m compileall -q backend/server.py agent/agent.py demo/gen_auth_log.py`
2. `cd frontend && npm run lint && npm run build`
3. For backend behavior changes: run the server with the demo log and test
   each mode you touched (`none`, `local`, `forward`) plus `/api/abusers`.
4. Commit with a conventional message: `feat|fix|chore|docs(scope): text`.
5. Push to `master` and confirm `ci` + `Docker Image CI-PROD master` are green.
6. Confirm the new Hub/GHCR tags exist before you claim success.

## 5. Git hooks

- Run `scripts/install-hooks.sh` once per clone. It installs:
  `commit-msg` (conventional format), `pre-commit` (compile + lint),
  `pre-push` (compile + frontend build). Do not use `--no-verify`.

## 6. Releases

- Only `scripts/release.sh X.Y.Z` cuts a release. It updates `VERSION`
  and `CHANGELOG.md`, commits, tags `vX.Y.Z`, and pushes.
- Never push tags by hand. Never edit a published release by hand.

## 7. Docs duty

- Each user-facing change updates `README.md`, `.env.example` if env changed,
  `SECURITY.md` if auth/privacy changed, and `CHANGELOG.md`.
- Keep docs in simplified English. Keep sentences short.
