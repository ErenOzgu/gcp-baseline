#!/usr/bin/env bash
# Plan one of the examples with a made-up access token and write the plan as JSON.
#
#   scripts/plan-example.sh examples/good plan.json
#
# Nothing is created and nothing real is contacted for credentials: `plan` only has to know what the
# configuration would create. Needs terraform (or tofu: TERRAFORM=tofu) and network access to download the
# google provider. The plan can contain secrets in a real project; the examples contain none.
set -euo pipefail

[ $# -eq 2 ] || {
  echo "usage: plan-example.sh DIR OUT.json" >&2
  exit 2
}
dir=$1
out=$2
tf=${TERRAFORM:-terraform}
export GOOGLE_OAUTH_ACCESS_TOKEN=${GOOGLE_OAUTH_ACCESS_TOKEN:-plan-only-token}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$tf" -chdir="$dir" init -backend=false -input=false -no-color > "$tmp/init.log" 2>&1 || {
  cat "$tmp/init.log" >&2
  exit 1
}
"$tf" -chdir="$dir" plan -input=false -lock=false -no-color -out="$tmp/plan.bin" > "$tmp/plan.log" 2>&1 || {
  cat "$tmp/plan.log" >&2
  exit 1
}
"$tf" -chdir="$dir" show -json "$tmp/plan.bin" > "$out"
