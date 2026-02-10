#!/usr/bin/env bash
set -euo pipefail

DOCKERHUB_NS="${DOCKERHUB_NS:-encode}"
IMAGE_NAME="${IMAGE_NAME:-iptv-au}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD)}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILDER_NAME="${BUILDER_NAME:-multiarch}"
RUN_LOGIN="${RUN_LOGIN:-1}"
VERIFY_PUSH="${VERIFY_PUSH:-1}"

usage() {
  cat <<'EOF'
Usage: ./build.sh [options]

Build and push a multi-arch Docker image to Docker Hub.

Options:
  --namespace <name>     Docker Hub namespace/user (default: encode)
  --image-name <name>    Repository/image name (default: iptv-au)
  --tag <tag>            Extra image tag besides latest (default: git short SHA)
  --platforms <list>     Build platforms (default: linux/amd64,linux/arm64,linux/arm/v7)
  --builder <name>       buildx builder name (default: multiarch)
  --no-login             Skip docker login step
  --no-verify            Skip manifest inspect step after push
  -h, --help             Show this help

Environment overrides:
  DOCKERHUB_NS, IMAGE_NAME, IMAGE_TAG, PLATFORMS, BUILDER_NAME, RUN_LOGIN, VERIFY_PUSH
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      DOCKERHUB_NS="$2"
      shift 2
      ;;
    --image-name)
      IMAGE_NAME="$2"
      shift 2
      ;;
    --tag)
      IMAGE_TAG="$2"
      shift 2
      ;;
    --platforms)
      PLATFORMS="$2"
      shift 2
      ;;
    --builder)
      BUILDER_NAME="$2"
      shift 2
      ;;
    --no-login)
      RUN_LOGIN=0
      shift
      ;;
    --no-verify)
      VERIFY_PUSH=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker command not found." >&2
  exit 1
fi

IMAGE="${DOCKERHUB_NS}/${IMAGE_NAME}"
echo "Image: ${IMAGE}"
echo "Tag: ${IMAGE_TAG}"
echo "Platforms: ${PLATFORMS}"
echo "Builder: ${BUILDER_NAME}"

if [[ "${RUN_LOGIN}" == "1" ]]; then
  docker login
fi

docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use 2>/dev/null || docker buildx use "${BUILDER_NAME}"
docker buildx inspect --bootstrap >/dev/null

docker buildx build \
  --platform "${PLATFORMS}" \
  --tag "${IMAGE}:latest" \
  --tag "${IMAGE}:${IMAGE_TAG}" \
  --push \
  .

if [[ "${VERIFY_PUSH}" == "1" ]]; then
  docker buildx imagetools inspect "${IMAGE}:latest"
fi

echo "Push complete:"
echo "  ${IMAGE}:latest"
echo "  ${IMAGE}:${IMAGE_TAG}"
