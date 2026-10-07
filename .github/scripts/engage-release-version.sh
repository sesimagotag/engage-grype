#!/usr/bin/env bash
# Map a stable anchore/grype tag v0.M.P to the engage tag v1.M.P.
# With no argument, uses the latest stable v0 release.
# Prints two shell assignments: upstream=... and engage=...
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: engage-release-version.sh [v0.M.P]" >&2
  exit 2
fi

if [[ $# -eq 1 && -n "$1" ]]; then
  upstream="$1"
else
  upstream="$(
    gh release list \
      --repo anchore/grype \
      --exclude-drafts \
      --exclude-pre-releases \
      --limit 40 \
      --json tagName \
      --jq '[.[] | select(.tagName | test("^v0\\.[0-9]+\\.[0-9]+$"))][0].tagName'
  )"
fi

if [[ ! "$upstream" =~ ^v0\.[0-9]+\.[0-9]+$ ]]; then
  echo "upstream tag must be a stable v0.M.P release, got: ${upstream:-<empty>}" >&2
  exit 1
fi

read -r draft prerelease <<<"$(
  gh release view "$upstream" \
    --repo anchore/grype \
    --json isDraft,isPrerelease \
    --jq '[.isDraft, .isPrerelease] | @tsv'
)"
if [[ "$draft" != "false" || "$prerelease" != "false" ]]; then
  echo "refusing draft or prerelease upstream tag: $upstream" >&2
  exit 1
fi

engage="v1${upstream#v0}"
printf 'upstream=%q\nengage=%q\n' "$upstream" "$engage"
