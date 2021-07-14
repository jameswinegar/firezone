#!/usr/bin/env bash
set -e

docker buildx build \
  --no-cache \
  --push \
  --platform linux/arm64,linux/amd64 \
  --tag ghcr.io/firezone/ubuntu:20.04 \
  --build-arg BASE_IMAGE="ubuntu:20.04" \
  --progress plain \
  -f pkg/Dockerfile.base.deb \
  .
