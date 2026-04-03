#!/usr/bin/env sh

set -eu

MODE="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi

LOCAL_IMAGE="${LOCAL_IMAGE:-openai-cpa-local:latest}"
LOCAL_CONTAINER_NAME="${LOCAL_CONTAINER_NAME:-wenfxl_codex_manager}"
NO_CACHE_BUILD=0

BUILD_PROXY="${BUILD_PROXY:-${HTTP_PROXY:-${http_proxy:-}}}"
BUILD_HTTPS_PROXY="${BUILD_HTTPS_PROXY:-${HTTPS_PROXY:-${https_proxy:-}}}"
BUILD_ALL_PROXY="${BUILD_ALL_PROXY:-${ALL_PROXY:-${all_proxy:-}}}"
BUILD_NO_PROXY="${BUILD_NO_PROXY:-${NO_PROXY:-${no_proxy:-}}}"

usage() {
    echo
    echo "Usage:"
    echo "  ./run-compose.sh local [--no-cache] [--proxy URL] [--https-proxy URL] [--all-proxy URL] [--no-proxy LIST]"
    echo "                              Build from local source and start"
    echo "  ./run-compose.sh remote      Start with the current remote image"
    echo "  ./run-compose.sh pull        Pull the latest remote image and start"
    echo "  ./run-compose.sh down        Stop and remove containers"
    echo "  ./run-compose.sh logs        Show live logs"
    echo
    echo "Examples:"
    echo "  ./run-compose.sh local --proxy http://127.0.0.1:7890"
    echo "  ./run-compose.sh local --no-cache"
    echo "  BUILD_PROXY=http://127.0.0.1:7890 ./run-compose.sh local"
    echo
}

compose_local() {
    docker compose -f docker-compose.yml -f docker-compose.local.yml "$@"
}

setup_build_proxy() {
    if [ -n "$BUILD_PROXY" ] && [ -z "$BUILD_HTTPS_PROXY" ]; then
        BUILD_HTTPS_PROXY="$BUILD_PROXY"
    fi
    if [ -n "$BUILD_PROXY" ] && [ -z "$BUILD_ALL_PROXY" ]; then
        BUILD_ALL_PROXY="$BUILD_PROXY"
    fi

    if [ -n "$BUILD_PROXY$BUILD_HTTPS_PROXY$BUILD_ALL_PROXY$BUILD_NO_PROXY" ]; then
        if [ -n "$BUILD_PROXY" ]; then
            export HTTP_PROXY="$BUILD_PROXY" http_proxy="$BUILD_PROXY"
        fi
        if [ -n "$BUILD_HTTPS_PROXY" ]; then
            export HTTPS_PROXY="$BUILD_HTTPS_PROXY" https_proxy="$BUILD_HTTPS_PROXY"
        fi
        if [ -n "$BUILD_ALL_PROXY" ]; then
            export ALL_PROXY="$BUILD_ALL_PROXY" all_proxy="$BUILD_ALL_PROXY"
        fi
        if [ -n "$BUILD_NO_PROXY" ]; then
            export NO_PROXY="$BUILD_NO_PROXY" no_proxy="$BUILD_NO_PROXY"
        fi

        echo "[INFO] Build proxy enabled for local image build."
        if [ -n "$BUILD_PROXY" ]; then
            echo "[INFO] HTTP_PROXY=$BUILD_PROXY"
        fi
        if [ -n "$BUILD_HTTPS_PROXY" ]; then
            echo "[INFO] HTTPS_PROXY=$BUILD_HTTPS_PROXY"
        fi
        if [ -n "$BUILD_ALL_PROXY" ]; then
            echo "[INFO] ALL_PROXY=$BUILD_ALL_PROXY"
        fi
        if [ -n "$BUILD_NO_PROXY" ]; then
            echo "[INFO] NO_PROXY=$BUILD_NO_PROXY"
        fi
    fi

    return 0
}

if [ -z "$MODE" ]; then
    usage
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] Docker command not found. Make sure Docker is installed and available in PATH."
    exit 1
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --proxy)
            [ "$#" -ge 2 ] || { echo "[ERROR] Missing value for --proxy"; exit 1; }
            BUILD_PROXY="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE_BUILD=1
            shift
            ;;
        --https-proxy)
            [ "$#" -ge 2 ] || { echo "[ERROR] Missing value for --https-proxy"; exit 1; }
            BUILD_HTTPS_PROXY="$2"
            shift 2
            ;;
        --all-proxy)
            [ "$#" -ge 2 ] || { echo "[ERROR] Missing value for --all-proxy"; exit 1; }
            BUILD_ALL_PROXY="$2"
            shift 2
            ;;
        --no-proxy)
            [ "$#" -ge 2 ] || { echo "[ERROR] Missing value for --no-proxy"; exit 1; }
            BUILD_NO_PROXY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unsupported option: $1"
            usage
            exit 1
            ;;
    esac
done

case "$MODE" in
    local)
        echo "[INFO] Build from local source and start containers..."
        setup_build_proxy
        if [ "$NO_CACHE_BUILD" -eq 1 ]; then
            echo "[INFO] Local build will ignore Docker cache."
            echo "[INFO] Step 1/3: explicit build for local image (codex-web, --no-cache)..."
            compose_local build --no-cache codex-web
        else
            echo "[INFO] Step 1/3: explicit build for local image (codex-web)..."
            compose_local build codex-web
        fi
        echo "[INFO] Step 2/3: recreate local service with freshly built image..."
        compose_local up -d --force-recreate --no-build codex-web
        echo "[INFO] Step 3/3: verify the running container image..."
        RUNNING_IMAGE="$(docker inspect "$LOCAL_CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || true)"
        if [ -n "$RUNNING_IMAGE" ]; then
            echo "[INFO] Container $LOCAL_CONTAINER_NAME is using image: $RUNNING_IMAGE"
            if [ "$RUNNING_IMAGE" != "$LOCAL_IMAGE" ]; then
                echo "[WARNING] Expected local image $LOCAL_IMAGE, but found $RUNNING_IMAGE"
                echo "[WARNING] The running container may still be using an old/remote image."
            fi
        else
            echo "[WARNING] Unable to inspect container $LOCAL_CONTAINER_NAME after startup."
        fi
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
