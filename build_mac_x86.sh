#!/usr/bin/env bash
set -euo pipefail

echo "[mailio] Configuring (macOS x86_64)…"
rm -rf build_x86_64

cmake -S . -B build_x86_64 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DOPENSSL_USE_STATIC_LIBS=ON \
  -DMAILIO_BUILD_DOCUMENTATION=OFF \
  -DMAILIO_BUILD_EXAMPLES=OFF \
  -DMAILIO_BUILD_TESTS=OFF \
  -DMAILIO_TEST_HOOKS=ON

echo "[mailio] Building (Release)…"
cmake --build build_x86_64 --config Release --parallel

echo "[mailio] Done."
