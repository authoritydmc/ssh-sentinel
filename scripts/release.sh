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

# 1) VERSION file plus workspace crate version (single source of truth)
printf '%s\n' "$VER" > VERSION
sed -i "s/^version = \"[0-9][0-9.]*\"$/version = \"$VER\"/" Cargo.toml
grep -q "^version = \"$VER\"$" Cargo.toml || { echo "[FAIL] Cargo.toml version bump failed." >&2; exit 1; }

# 2) CHANGELOG: move the Unreleased body under a versioned heading,
# keep a fresh Unreleased stub (file starts with a title preamble).
awk -v ver="$VER" -v today="$TODAY" '
  /^## \[Unreleased\]$/ && !done { print; print ""; print "## [" ver "] - " today; done=1; next }
  { print }
' CHANGELOG.md > CHANGELOG.md.new && mv CHANGELOG.md.new CHANGELOG.md
grep -q "^## \[$VER\] - $TODAY$" CHANGELOG.md || { echo "[FAIL] CHANGELOG rewrite failed." >&2; exit 1; }

# 3) Refresh the workspace lockfile for the new version (offline, no network).
cargo metadata --format-version 1 --no-deps >/dev/null

git add VERSION CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "chore(release): v$VER"
git tag -a "v$VER" -m "v$VER"
git push origin master "v$VER"
echo "Released v$VER — watch: gh run list --limit 4"
