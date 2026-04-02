#!/usr/bin/env sh

set -eu

MODE="${1:-}"

usage() {
    echo
    echo "Usage:"
    echo "  ./run-compose.sh local   <-- Build from local source and start"
    echo "  ./run-compose.sh remote  <-- Start with the current remote image"
    echo "  ./run-compose.sh pull    <-- Pull the latest remote image and start"
    echo "  ./run-compose.sh down    <-- Stop and remove containers"
    echo "  ./run-compose.sh logs    <-- Show live logs"
    echo
}

if [ -z "$MODE" ]; then
    usage
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] Docker command not found. Make sure Docker is installed and available in PATH."
    exit 1
fi

case "$MODE" in
    local)
        echo "[INFO] Build from local source and start containers..."
        docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build --force-recreate
        ;;
    remote)
        echo "[INFO] Start containers with the current remote image..."
        docker compose up -d
        ;;
    pull)
        echo "[INFO] Pull the latest remote image and recreate containers..."
        docker compose pull
        docker compose up -d --force-recreate
        ;;
    down)
        echo "[INFO] Stop and remove containers..."
        docker compose down
        ;;
    logs)
        echo "[INFO] Follow container logs..."
        docker compose logs -f
        ;;
    *)
        echo "[ERROR] Unsupported mode: $MODE"
        usage
        exit 1
        ;;
esac
