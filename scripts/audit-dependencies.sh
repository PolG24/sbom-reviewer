#!/bin/sh
set -eu

requirements_file=$(mktemp)
trap 'rm -f "$requirements_file"' EXIT HUP INT TERM

# Export every locked runtime and development dependency, excluding only the
# local application package. The lock export includes pinned versions and hashes.
uv export \
    --locked \
    --all-groups \
    --no-emit-project \
    --format requirements-txt \
    --output-file "$requirements_file"

uv run --locked pip-audit --strict --require-hashes -r "$requirements_file"
