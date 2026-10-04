#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# == 0 ]]; then set -- -t=test; fi
python3 tools/report.py validate "$@"
endly -r=run -t=build
trap './.bin/fixture stop' EXIT
mkdir -p reports
report=$(mktemp "reports/run-XXXXXXXX")
mv "$report" "$report.log"
report="$report.log"
endly -r=run "$@" 2>&1 | tee "$report"
python3 tools/report.py verify "$report" "$@"
