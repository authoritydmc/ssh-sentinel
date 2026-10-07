---
name: pr-writing
description: Write pull request descriptions in ASD-STE100 Simplified Technical English. Use when you open, update, or review a PR in this repo.
---

# PR writing skill (ASD-STE100)

## Language rules

- Use short sentences. Limit: 20 words per sentence.
- Give one fact per sentence. No compound claims.
- Use verbs in simple present. Avoid -ing forms where possible.
- Use the same term for the same thing. See `docs/ARCHITECTURE.md`.
- No idioms. No jokes. No marketing words (blazing, seamless, robust).
- You may break these rules only for code, commands, and exact error text.

## Required structure

```markdown
## Purpose

<2-4 sentences. State the problem, then the fix.>

## Changes

- <file or area>: <what changed, one line each>

## Verification

- [ ] <check + result, e.g. `cargo test -p ssh-sentinel` 12/12 pass>
- [ ] CI runs linked: ci + Docker Image CI-PROD master are green

## Tracker

Relates to #<n> (or: Closes #<n> only when the issue is fully done)
```

## Good vs bad

Bad: "This massively overhauls the incredibly flaky auth flow to seamlessly support SSO."

Good: "Local login blocked SSO users. This PR adds an OIDC code flow. Authentik is the tested provider."

## Checklist before you open the PR

1. Every claim in Purpose has proof in Verification.
2. No secrets, tokens, hashes, or real host names in the text.
3. `Closes` only when all acceptance boxes of the issue are ticked.
   Else use `Relates to`.
4. Link the green runs. Do not claim success before tags exist.
