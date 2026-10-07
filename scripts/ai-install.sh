#!/bin/sh
# SSH Sentinel AI bootstrap. Safe to pipe from the README one-liner:
#   curl -fsSL https://raw.githubusercontent.com/authoritydmc/ssh-sentinel/master/scripts/ai-install.sh | bash
# It clones (or updates) the repo, installs git hooks, seeds .env,
# then prints the AI operator prompt from AI.md.
set -eu
REPO="${REPO:-authoritydmc/ssh-sentinel}"
BRANCH="${BRANCH:-master}"
DIR="${DIR:-ssh-sentinel}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing: $1 ($2)" >&2
    MISSING=1
  fi
}
MISSING=0
need git "install git first"
need docker "install docker for compose deploys"
need cargo "needed for Rust checks (or use WSL per skills/rust-wsl/SKILL.md)"
[ "${MISSING:-0}" = 1 ] && echo "fix the missing tools, then re-run." >&2

if [ -d "$DIR/.git" ]; then
  echo "repo exists at ./$DIR — updating to $BRANCH"
  git -C "$DIR" fetch origin
  git -C "$DIR" checkout "$BRANCH"
  git -C "$DIR" pull --ff-only origin "$BRANCH" || true
else
  git clone --branch "$BRANCH" "https://github.com/${REPO}.git" "$DIR"
fi
cd "$DIR"

if [ -f scripts/install-hooks.sh ]; then
  sh scripts/install-hooks.sh
fi
if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
  echo "created .env from .env.example — edit it next"
fi

echo ""
echo "--- paste this into your AI ---"
sed -n '/^```text$/,/^```$/p' AI.md | sed '1d;$d'
