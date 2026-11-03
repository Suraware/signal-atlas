#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  echo 'The local Python environment is missing. From the project folder, run:' >&2
  echo '  uv sync --frozen --extra dev' >&2
  exit 1
fi

help_requested=false
for argument in "$@"; do
  if [[ "$argument" == --help || "$argument" == -h ]]; then
    help_requested=true
  fi
done

if [[ "$help_requested" == false && ! -f frontend/dist/index.html ]]; then
  echo 'The local interface has not been built. From the project folder, run:' >&2
  echo '  npm --prefix frontend ci' >&2
  echo '  npm --prefix frontend run build' >&2
  exit 1
fi

export PYTHONPATH="$ROOT/backend${PYTHONPATH:+:$PYTHONPATH}"
exec .venv/bin/python -u -m atlas.cli "$@"
