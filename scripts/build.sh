#!/bin/bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"
bash scripts/build_compat.sh
python3 scripts/port_ipa.py --shim build/libmcmac.dylib "$@"
