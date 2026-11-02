#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <owner/repo> <branch>" >&2
  exit 2
fi

repository=$1
branch=$2

if [[ ! $repository =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid repository; expected owner/repo" >&2
  exit 2
fi

encoded_branch=$(python3 - "$branch" <<'PY'
import sys
from urllib.parse import quote

print(quote(sys.argv[1], safe=""))
PY
)

gh api "repos/${repository}/rules/branches/${encoded_branch}"
