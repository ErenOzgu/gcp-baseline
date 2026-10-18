#!/usr/bin/env bash
# Check that README.md says what the repository does:
#   - the rules table is the one the policy generates (scripts/rules-table.sh)
#   - every <!-- include:PATH --> marker is followed by a fenced block with exactly the content of PATH
#   - every input variable of the module is mentioned in backticks
#   - the numbers of policy tests and refused inputs that the README states are the real ones
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readme="$root/README.md"
status=0

"$root/scripts/rules-table.sh" --check || status=1

while IFS= read -r path; do
  [ -f "$root/$path" ] || {
    echo "check-readme.sh: README includes $path, which does not exist" >&2
    status=1
    continue
  }
  got=$(awk -v marker="<!-- include:${path} -->" '
    $0 == marker { armed = 1; next }
    armed && /^```/ { if (!inside) { inside = 1; next } else { exit } }
    inside { print }
  ' "$readme")
  want=$(cat "$root/$path")
  if [ -z "$got" ] || [ "$got" != "$want" ]; then
    echo "check-readme.sh: the block after <!-- include:${path} --> is not the content of ${path}" >&2
    diff <(printf '%s\n' "$got") <(printf '%s\n' "$want") >&2 || true
    status=1
  fi
done < <(grep -o '<!-- include:[^ ]* -->' "$readme" | sed 's/^<!-- include:\(.*\) -->$/\1/')

while IFS= read -r name; do
  grep -q "\`${name}\`" "$readme" || {
    echo "check-readme.sh: the input ${name} is not described in README.md" >&2
    status=1
  }
done < <(sed -n 's/^variable "\([a-z_]*\)".*/\1/p' "$root/modules/baseline/variables.tf")

opa=${OPA:-opa}
stated=$(sed -n 's/.*policy has \([0-9][0-9]*\) unit tests.*/\1/p' "$readme")
actual=$("$opa" test "$root/policy" | sed -n 's/^PASS: \([0-9][0-9]*\)\/.*/\1/p')
if [ -z "$stated" ] || [ "$stated" != "$actual" ]; then
  echo "check-readme.sh: the README says ${stated:-nothing} policy unit tests, there are ${actual:-unknown}" >&2
  status=1
fi
stated=$(sed -n 's/.*and \([0-9][0-9]*\) bad inputs.*/\1/p' "$readme")
actual=$(grep -c 'expect_failures' "$root/modules/baseline/tests/baseline.tftest.hcl" || true)
if [ -z "$stated" ] || [ "$stated" != "$actual" ]; then
  echo "check-readme.sh: the README says ${stated:-nothing} refused bad inputs, there are ${actual}" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "README is in step with the code"
fi
exit "$status"
