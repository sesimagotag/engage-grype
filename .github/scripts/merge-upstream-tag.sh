#!/usr/bin/env bash
# Merge a stable anchore/grype release tag into the current Engage branch.
#
# The .github tree is owned by this fork: upstream workflows must not be
# re-enabled by a sync. Any conflict outside .github stops the merge so an
# upstream change cannot silently overwrite Engage code.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^v0\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: merge-upstream-tag.sh v0.M.P" >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree must be clean before syncing upstream" >&2
  exit 1
fi

upstream_tag="$1"
base_sha="$(git rev-parse HEAD)"

git fetch --no-tags https://github.com/anchore/grype.git "refs/tags/${upstream_tag}"
upstream_sha="$(git rev-parse 'FETCH_HEAD^{commit}')"

if git merge-base --is-ancestor "$upstream_sha" HEAD; then
  echo "${upstream_tag} (${upstream_sha}) is already merged"
  exit 0
fi

set +e
git merge --no-ff --no-commit "$upstream_sha"
merge_status=$?
set -e

# Keep the complete Engage-owned GitHub configuration. Removing the merged
# tree first also drops workflows newly added upstream.
git rm -r -f --ignore-unmatch .github
git checkout "$base_sha" -- .github
git add .github

mapfile -t conflicts < <(git diff --name-only --diff-filter=U)
if (( ${#conflicts[@]} > 0 )); then
  printf 'upstream merge has conflicts outside .github:\n' >&2
  printf '  %s\n' "${conflicts[@]}" >&2
  exit 1
fi

if (( merge_status != 0 )); then
  echo "resolved upstream conflicts in the Engage-owned .github tree"
fi

git \
  -c user.name='github-actions[bot]' \
  -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  commit -m "chore: sync with anchore/grype ${upstream_tag}"

echo "merged ${upstream_tag} (${upstream_sha}) into $(git rev-parse HEAD)"
