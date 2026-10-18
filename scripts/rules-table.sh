#!/usr/bin/env bash
# Print the table of rules from policy/baseline.rego, or check that README.md contains exactly that table.
#
#   scripts/rules-table.sh           print the table
#   scripts/rules-table.sh --check   compare it with the block between the rules markers in README.md
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
opa=${OPA:-opa}

table() {
  echo "| Rule | What it requires |"
  echo "| --- | --- |"
  "$opa" eval --format raw --data "$root/policy/baseline.rego" \
    'concat("\n", [sprintf("| %s | %s |", [id, text]) | some id, text in data.baseline.rules])' |
    sort
}

case "${1:-}" in
  "") table ;;
  --check)
    readme="$root/README.md"
    got=$(awk '/<!-- rules:start -->/{on=1; next} /<!-- rules:end -->/{on=0} on' "$readme")
    want=$(table)
    if [ "$got" != "$want" ]; then
      echo "rules-table.sh: the table in README.md is out of date; it should be:" >&2
      diff <(printf '%s\n' "$got") <(printf '%s\n' "$want") >&2 || true
      exit 1
    fi
    echo "README rules table is current"
    ;;
  *)
    echo "usage: rules-table.sh [--check]" >&2
    exit 2
    ;;
esac
