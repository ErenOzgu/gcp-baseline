#!/usr/bin/env bash
# Judge a Terraform plan with policy/baseline.rego.
#
#   terraform plan -out=plan.bin && terraform show -json plan.bin > plan.json
#   scripts/check-plan.sh plan.json
#
# Prints one line per violation, "RULE resource: message". Exit status: 0 no violations, 1 violations,
# 2 the input is not a plan or the tool is missing or misused.
set -euo pipefail

usage() {
  echo "usage: check-plan.sh PLAN.json [--expect FILE]" >&2
  echo "  --expect FILE  succeed only when the report is exactly the content of FILE (used on the examples)" >&2
  exit 2
}

plan=""
expect=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expect)
      [ $# -ge 2 ] || usage
      expect=$2
      shift 2
      ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
      [ -z "$plan" ] || usage
      plan=$1
      shift
      ;;
  esac
done
[ -n "$plan" ] || usage

opa=${OPA:-opa}
command -v "$opa" > /dev/null 2>&1 || {
  echo "check-plan.sh: opa not found; set OPA=/path/to/opa or put it on PATH" >&2
  exit 2
}
[ -f "$plan" ] || {
  echo "check-plan.sh: $plan: no such file" >&2
  exit 2
}

policy="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/policy"
rego=("$opa" eval --format raw --data "$policy/baseline.rego" --input "$plan")

# `eval` prints the value of the query; an undefined query prints nothing and exits 0 with --fail off.
if [ "$("${rego[@]}" 'data.baseline.looks_like_plan' 2> /dev/null || true)" != "true" ]; then
  echo "check-plan.sh: $plan does not look like the output of 'terraform show -json PLAN'" >&2
  exit 2
fi

report=$("${rego[@]}" 'data.baseline.report')

if [ -n "$expect" ]; then
  if [ "$report" = "$(cat "$expect")" ]; then
    echo "report matches $expect"
    exit 0
  fi
  echo "report differs from $expect:" >&2
  diff <(printf '%s\n' "$report") "$expect" >&2 || true
  exit 1
fi

if [ -n "$report" ]; then
  printf '%s\n' "$report"
  exit 1
fi
echo "no violations"
