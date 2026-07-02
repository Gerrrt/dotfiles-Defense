#!/usr/bin/env bash
# detections/navigator/gen-navigator.sh — generate a MITRE ATT&CK Navigator layer
# from the Sigma rules' technique tags, so detection coverage is a versioned artifact.
# ──────────────────────────────────────────────────────────────────────────────
# Sigma is the source of truth (detections/sigma/). Every rule carries its ATT&CK
# technique as `attack.tXXXX[.YYY]` tags; this rolls them up into a Navigator layer
# (coverage-layer.json) you can drop into https://mitre-attack.github.io/attack-navigator/
# to see the corpus's coverage on the ATT&CK matrix. Each covered technique is scored
# by how many rules detect it (gradient white→blue) and commented with the rule names.
#
#   gen-navigator.sh            # (re)write navigator/coverage-layer.json from sigma/
#   gen-navigator.sh --check    # exit 1 (with a diff) if the committed layer is stale
#
# --check is the drift gate (CI runs it in .github/workflows/sigma.yml); the bare form
# is what you run after adding/retagging a rule. Pure stdlib Python — no extra deps
# beyond the python3 the sigma job already installs.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
SIGMA="$HERE/../sigma"
OUT="$HERE/coverage-layer.json"

CHECK=0
if [[ $# -gt 1 ]]; then
  echo "gen-navigator: too many arguments" >&2
  echo "usage: gen-navigator.sh [--check]" >&2
  exit 2
fi
case "${1:-}" in
"") CHECK=0 ;;
--check) CHECK=1 ;;
*)
  echo "gen-navigator: unknown argument '$1'" >&2
  echo "usage: gen-navigator.sh [--check]" >&2
  exit 2
  ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "gen-navigator: python3 not found" >&2
  exit 1
fi

generate() {
  SIGMA_DIR="$SIGMA" python3 - <<'PY'
import glob, json, os, re

sigma = os.environ["SIGMA_DIR"]
tech_re = re.compile(r'attack\.(t\d+(?:\.\d+)?)', re.IGNORECASE)
title_re = re.compile(r'^title:\s*(.+?)\s*$', re.MULTILINE)

# technique id (T-upper) -> sorted set of rule stems that tag it
cover = {}
for path in sorted(glob.glob(os.path.join(sigma, "*", "*.yml"))):
    text = open(path, encoding="utf-8").read()
    stem = os.path.splitext(os.path.basename(path))[0]
    for m in tech_re.finditer(text):
        tid = "T" + m.group(1)[1:].upper()
        cover.setdefault(tid, set()).add(stem)

techniques = []
max_score = 0
for tid in sorted(cover):
    rules = sorted(cover[tid])
    max_score = max(max_score, len(rules))
    techniques.append({
        "techniqueID": tid,
        "score": len(rules),
        "enabled": True,
        "comment": "{} rule(s): {}".format(len(rules), ", ".join(rules)),
    })

layer = {
    "name": "dotfiles-Defense — detection coverage",
    "description": "Generated from detections/sigma/ by gen-navigator.sh. Score = number "
                   "of Sigma rules detecting each ATT&CK technique.",
    "domain": "enterprise-attack",
    "versions": {"attack": "16", "navigator": "4.9.5", "layer": "4.5"},
    "techniques": techniques,
    "gradient": {
        "colors": ["#ffffff", "#66b1ff"],
        "minValue": 0,
        "maxValue": max_score if max_score else 1,
    },
    "legendItems": [],
    "showTacticRowBackground": False,
    "hideDisabled": False,
}
print(json.dumps(layer, indent=2, ensure_ascii=True))
PY
}

if [[ "$CHECK" -eq 1 ]]; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  generate >"$tmp"
  if ! diff -u "$OUT" "$tmp" >/dev/null 2>&1; then
    echo "gen-navigator: $OUT is out of date — run detections/navigator/gen-navigator.sh" >&2
    diff -u "$OUT" "$tmp" >&2 || true
    exit 1
  fi
  echo "gen-navigator: coverage-layer.json up to date"
else
  generate >"$OUT"
  echo "gen-navigator: wrote $OUT"
fi
