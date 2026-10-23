#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/deploy/compose"

echo "=== Stopping Tijeri Platform ==="

docker compose -f docker-compose.full.yml stop
docker compose -f docker-compose.full.yml down --remove-orphans

echo "=== All services stopped ==="