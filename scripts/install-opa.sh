#!/usr/bin/env bash
# Install Open Policy Agent at the version this repository is tested with, after checking the download against
# a SHA-256 written down here. Linux on x86-64 only.
#
#   sudo scripts/install-opa.sh            # into /usr/local/bin
#   scripts/install-opa.sh "$HOME/bin"     # into another directory
set -euo pipefail

version=1.4.2
sha256=2c0ccdbbe0b8e2a5d12d9c42d92f1f34f494ffb32d1f3c4ddc36101be637d66f
dest=${1:-/usr/local/bin}

[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || {
  echo "install-opa.sh: only Linux on x86-64 is supported here; get opa ${version} from https://www.openpolicyagent.org/docs/latest/#running-opa" >&2
  exit 2
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/opa" "https://github.com/open-policy-agent/opa/releases/download/v${version}/opa_linux_amd64_static"
echo "${sha256}  ${tmp}/opa" | sha256sum -c -
install -m 0755 "$tmp/opa" "${dest}/opa"
"${dest}/opa" version | head -1
