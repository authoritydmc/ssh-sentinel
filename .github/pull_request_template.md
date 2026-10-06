## What / why (scenario)

## Changes

- [ ] backend (`server.py`, stdlib-only — no new runtime deps)
- [ ] agent
- [ ] frontend (`npm run lint` + `npm run build` clean)
- [ ] docs (README / SECURITY / CHANGELOG / `.env.example`)

## Verification

- [ ] `python3 -m compileall -q backend/server.py agent/agent.py`
- [ ] `./test_docker.sh` (covers open + local-auth + abusers safety)
- [ ] CI + Docker workflow runs linked below
- [ ] Docker Hub / GHCR tags checked

## Tracker

Closes / relates to #… (umbrella issue #1 for the public-ready track)
