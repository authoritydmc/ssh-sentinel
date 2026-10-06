# SSH Sentinel — system architecture

> Style note: this document uses ASD-STE100 simplified English.
> Sentences are short. Each sentence has one idea.
> Procedures use numbered steps. Terms are defined once and reused.

## 1. Purpose

SSH Sentinel shows SSH attacks on one server or on many servers.
It collects auth logs. It counts failed logins.
It enriches attacker IPs with geo and intel data.
It presents the result in a web dashboard.

## 2. Terms

| Term | Meaning |
| ---- | ------- |
| central | The main container. It stores logs and serves the API and the UI. |
| agent | A lightweight shipper. It tails a log and pushes new lines to central. |
| member | A server that runs an agent. Members open no inbound ports. |
| fleet | One central plus zero or more agents. |
| scope | The data filter in the UI: the full fleet or one host. |

## 3. System context

```mermaid
flowchart LR
    subgraph fleet[Fleet]
        A1[member: agent] -->|HTTPS + Bearer<br/>outbound only| C[central :8079]
        A2[member: agent] -->|HTTPS + Bearer<br/>outbound only| C
        LOG[/var/log/auth.log<br/>central host] --> C
    end
    C -->|React UI + JSON API| OP[operator]
    SSO[SSO: Authentik / Authelia / Cloudflare Access] -->|ForwardAuth<br/>identity headers| C
    C -->|optional| RC[recon provider:<br/>SpiderFoot / webhook]
    RC -->|geo / RDAP / rDNS| EXT[(ip-api, RDAP, rDNS)]
```

Rules:

- Agents start the connection. Central never connects to agents.
- Members need no open ports. They need outbound HTTPS to central.
- Central serves the UI and the API on port 8079.
- Keep port 8079 in a private network. Or put SSO in front of it.

## 4. Container roles

One image serves two roles. `ROLE` selects the role.

| ROLE | Process | Inputs | Outputs |
| ---- | ------- | ------ | ------- |
| `central` (default) | `server.py` | host log, agent pushes | UI, JSON API, stored JSONL |
| `agent` | `agent.py` | host log, `CENTRAL_URL`, `AGENT_TOKEN` | filtered log lines to central |

```mermaid
flowchart TD
    IMG[image: rajlabs/ssh-sentinel] --> E{ROLE?}
    E -->|central| S[server.py<br/>ThreadingHTTPServer]
    E -->|agent| G[agent.py<br/>tail + push loop]
    S --> DIST[React dist/]
    S --> DATA[data/hosts/*.jsonl<br/>agents.json]
    G -->|Bearer push<br/>every PUSH_EVERY| S
```

## 5. Data flow

```mermaid
sequenceDiagram
    participant L as auth.log
    participant A as agent
    participant C as central
    participant U as UI / API client
    L->>A: new lines
    A->>A: keep sshd lines only
    A->>C: POST /api/agent/push (Bearer)
    C->>C: append JSONL, cap 60k lines
    U->>C: GET /api/summary?host=
    C->>C: parse, enrich geo, cache
    C->>U: totals, top IPs, timeline
```

Notes:

- The agent resumes from inode plus offset. It survives rotation and restarts.
- The server filters again on ingest. Old agents stay safe.
- Geo results stay in cache. The cache refreshes in the background.

## 6. Access control

```mermaid
flowchart TD
    R([request]) --> H{path?}
    H -->|/healthz, /api/auth| OK1[allow]
    H -->|/api/agent/push| BEAR[check Bearer token]
    H -->|other| M{AUTH_MODE?}
    M -->|none| OK2[allow: private net only]
    M -->|local| BA[check HTTP Basic<br/>pbkdf2 hash]
    M -->|forward / oidc| PX{from trusted proxy<br/>with SSO header?}
    PX -->|yes| OK3[allow]
    PX -->|no| D[deny 401/403]
    BA -->|bad| D
    BA -->|good| OK3
```

Rules:

- Default mode is `local`. It denies all requests without credentials.
- `forward` trusts SSO headers only from `AUTH_TRUSTED_PROXIES`.
- `/api/abusers` shows attacker data only. It never shows logins or host names.

## 7. Recon providers

```mermaid
flowchart TD
    IP([attacker IP]) --> P{RECON_PROVIDER?}
    P -->|spiderfoot| SF[SpiderFoot scan<br/>poll to FINISHED]
    P -->|webhook| WH[POST to hook<br/>normalize findings]
    P -->|none| OFF[disabled]
    SF --> K[(cache 7 days)]
    WH --> K
```

The webhook contract is small: send `{"ip": "1.2.3.4"}`,
receive `{"findings": [{"type": "...", "data": "...", "module": "..."}]}`.

## 8. Deployments

### 8.1. One server

1. Copy `.env.example` to `.env`.
2. Set `HOST_ID` and `AUTH_*` login values.
3. Run `docker compose up -d --build`.
4. Open `http://localhost:8079`.

### 8.2. Fleet on a tailnet

1. Start central on the main server.
2. Mint a token on central: `server.py gentoken <host>`.
3. Start an agent on each member with the token.
4. Check `/api/hosts` on central. All members must show `online`.

### 8.3. Fleet with SSO

1. Set `AUTH_MODE=forward` on central.
2. Put Traefik plus Authentik in front of central.
3. Use `examples/sso-traefik-authentik.yml` as a starting point.
4. Keep direct access to port 8079 closed.

## 9. Release flow

```mermaid
flowchart LR
    DEV[commit to master] --> CI[ci: lint + build + compile]
    DEV --> SMK[docker: smoke test<br/>open + login + abusers]
    SMK --> HUB[push :latest + :prod.SHA<br/>to Hub + GHCR]
    TAG[tag vX.Y.Z<br/>scripts/release.sh] --> SEM[semver images<br/>X.Y.Z, X.Y]
    TAG --> REL[GitHub Release<br/>notes from CHANGELOG]
```

Script `scripts/release.sh` updates `VERSION`, moves the
`Unreleased` section to a versioned section, commits, tags, and pushes.
