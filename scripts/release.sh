#!/usr/bin/env bash
# Cut a release: VERSION + CHANGELOG + tag + push (CI publishes images,
# release.yml publishes GitHub Release notes from the CHANGELOG section).
# Usage: ./scripts/release.sh 0.3.0
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:-}"
if ! [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <semver>   e.g. $0 0.3.0" >&2
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "[FAIL] working tree dirty — commit first." >&2
  exit 1
fi
if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
  echo "[FAIL] no '## [Unreleased]' section in CHANGELOG.md" >&2
  exit 1
fi
TODAY=$(date +%F)

# 1) VERSION file
printf '%s\n' "$VER" > VERSION

# 2) CHANGELOG: move the Unreleased body under a versioned heading,
# keep a fresh Unreleased stub (file starts with a title preamble).
python3 - "$VER" "$TODAY" <<'PY'
import sys
ver, today = sys.argv[1], sys.argv[2]
src = open("CHANGELOG.md").read()
old = "## [Unreleased]\n"
assert old in src, "CHANGELOG lacks an '## [Unreleased]' section"
head, rest = src.split(old, 1)
open("CHANGELOG.md", "w").write(
    head + "## [Unreleased]\n\n## [%s] - %s\n%s" % (ver, today, rest))
PY

git add VERSION CHANGELOG.md
git commit -m "chore(release): v$VER"
git tag -a "v$VER" -m "v$VER"
git push origin master "v$VER"
echo "Released v$VER — watch: gh run list --limit 4"
