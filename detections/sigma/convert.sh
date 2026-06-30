#!/usr/bin/env bash
# detections/sigma/convert.sh — compile every Sigma rule to a SIEM backend.
#
# Sigma is the source of truth; this is the "compile to your backend" step from
# DEFENSE-METHODOLOGY.md, made reproducible. It compiles each rule with the chosen
# pySigma backend (default: splunk) and prints the query per tactic dir. It is also
# the local twin of the CI smoke test in .github/workflows/sigma.yml, which runs the
# same `sigma convert` to prove every rule still compiles.
#
# --without-pipeline keeps raw logical field names (good for a compile/validation
# check). For DEPLOYABLE output, add a processing pipeline that maps fields to your
# data model, e.g.:  sigma convert -t splunk -p splunk_windows detections/sigma/<dir>/
#
# Usage:  detections/sigma/convert.sh [backend]      # default backend: splunk
# Deps:   sigma-cli + the backend plugin
#         pip install sigma-cli pysigma-backend-splunk
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
BACKEND="${1:-splunk}"

if ! command -v sigma >/dev/null 2>&1; then
  echo "sigma not found — pip install sigma-cli pysigma-backend-${BACKEND}" >&2
  exit 1
fi

rc=0
for dir in "$HERE"/*/; do
  [[ -d "$dir" ]] || continue
  printf '\n### %s\n' "$(basename "$dir")"
  sigma convert -t "$BACKEND" --without-pipeline "$dir" || rc=1
done
exit "$rc"
