#!/usr/bin/env bash
# Install this repo's git hooks (run once per clone).
set -euo pipefail
cd "$(dirname "$0")/.."
git config core.hooksPath .githooks
chmod +x .githooks/* scripts/*.sh
echo "hooks installed from .githooks (commit-msg, pre-commit, pre-push)"
