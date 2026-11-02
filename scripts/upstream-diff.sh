#!/usr/bin/env bash
# Show upstream changes to code we copied (docs/provenance.md), to spot security fixes to port.
set -euo pipefail

usage() {
  cat <<USAGE
Usage: scripts/upstream-diff.sh [--ref REF] [--ours] [--stat] [--upstream DIR]

For every row in docs/provenance.md, diff the upstream path between the recorded
commit and REF (default: origin/HEAD). Only rows with upstream changes are printed.

  --ref REF       upstream ref to compare against (default: origin/HEAD; run 'git fetch' in the clone first)
  --ours          instead, diff the recorded upstream version against our copy (shows our adaptations)
  --stat          print a diffstat instead of the full diff
  --upstream DIR  upstream clone (default: \$SOVEREIGN_SDK_DIR or ~/Projects/sovereign-sdk)
USAGE
}

root=$(cd "$(dirname "$0")/.." && pwd)
upstream=${SOVEREIGN_SDK_DIR:-$HOME/Projects/sovereign-sdk}
ref=origin/HEAD
mode=upstream
stat=()

while [ $# -gt 0 ]; do
  case $1 in
    --ref) ref=$2; shift 2 ;;
    --ours) mode=ours; shift ;;
    --stat) stat=(--stat); shift ;;
    --upstream) upstream=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

git -C "$upstream" rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git repo: $upstream" >&2; exit 1; }
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "${s//\`/}"; }

rows=$(sed -n '/<!-- provenance:begin -->/,/<!-- provenance:end -->/p' "$root/docs/provenance.md" \
  | grep '^|' | tail -n +3 || true)
[ -n "$rows" ] || { echo "no copied code recorded in docs/provenance.md"; exit 0; }
[ "$mode" = ours ] || git -C "$upstream" rev-parse --verify --quiet "$ref^{commit}" >/dev/null \
  || { echo "unknown upstream ref: $ref" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
changed=0

while IFS='|' read -r _ ours up commit _; do
  ours=$(trim "$ours"); up=$(trim "$up"); commit=$(trim "$commit")
  git -C "$upstream" rev-parse --verify --quiet "$commit^{commit}" >/dev/null \
    || { echo "!! $ours: unknown upstream commit $commit" >&2; changed=1; continue; }

  if [ "$mode" = upstream ]; then
    out=$(git -C "$upstream" diff "${stat[@]}" "$commit" "$ref" -- "$up")
    [ -z "$out" ] || { printf '== %s  <-  %s (%s..%s)\n%s\n\n' "$ours" "$up" "$commit" "$ref" "$out"; changed=1; }
  else
    snap="$tmp/$(printf '%s' "$ours" | tr '/' '_')"
    mkdir -p "$snap"
    git -C "$upstream" archive "$commit" -- "$up" | tar -x -C "$snap"
    out=$(diff -ruN "$snap/$up" "$root/$ours" || true)
    if [ -n "$out" ]; then
      [ ${#stat[@]} -eq 0 ] || out=$(printf '%s\n' "$out" | diffstat 2>/dev/null || printf '%s\n' "$out" | grep -c '^[-+][^-+]' | sed 's/$/ changed lines/')
      printf '== %s  vs  %s@%s\n%s\n\n' "$ours" "$up" "$commit" "$out"
    fi
  fi
done <<< "$rows"

[ "$mode" = ours ] || [ $changed -eq 0 ] || exit 1
