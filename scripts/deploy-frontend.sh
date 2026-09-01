#!/usr/bin/env bash
# Copy / remount frontend into the running rf-hunter-v2 container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${CONTAINER_NAME:-rf-hunter-v2}"

if ! docker info >/dev/null 2>&1; then
  echo "Need Docker access (add user to docker group, or run: sudo $0)" >&2
  exit 1
fi

# Prefer compose remount (./frontend bind) so future edits need no copy
if [[ -f "$ROOT/docker-compose.yml" ]]; then
  echo "Recreating $NAME with frontend bind-mount…"
  (cd "$ROOT" && docker compose up -d --force-recreate --no-build)
else
  docker cp "$ROOT/frontend/." "$NAME:/app/frontend/"
fi

echo "Done. Hard-refresh the web UI (Ctrl+Shift+R) at http://127.0.0.1:8081/"
