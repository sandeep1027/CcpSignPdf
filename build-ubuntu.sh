#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-ubuntu.sh — build ccpsignpdf on Ubuntu/Debian.
#
# WHY THIS SCRIPT EXISTS
#   The source targets the PoDoFo *0.10* API. Ubuntu 22.04's apt package
#   (libpodofo-dev) is PoDoFo *0.9.x*, whose API is incompatible — that
#   mismatch is exactly what produced the "CreateDictionaryObject / PdfVecObjects
#   / bufferview / SignDocument not declared" wall of errors. So unless the
#   distro already ships 0.10+, this script builds PoDoFo 0.10 FROM SOURCE and
#   installs it to /usr/local, then builds ccpsignpdf against that.
#
#   It deliberately avoids the vcpkg path (vcpkg's gperf port was failing to
#   build on the user's box, so PoDoFo 0.10 never got produced there).
#
# Re-runnable. Run as a sudo-capable user (or root).
# ---------------------------------------------------------------------------
set -euo pipefail

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PODOFO_PREFIX="${PODOFO_PREFIX:-/usr/local}"
PODOFO_SRC="${PODOFO_SRC:-$HOME/podofo-src}"
JOBS="$(nproc 2>/dev/null || echo 2)"

echo "==> [1/5] Install build tooling + PoDoFo's transitive dependencies"
$SUDO apt-get update
$SUDO apt-get install -y \
  build-essential cmake git pkg-config \
  libssl-dev libcurl4-openssl-dev \
  libfreetype-dev libfontconfig1-dev zlib1g-dev libxml2-dev \
  libjpeg-dev libpng-dev libtiff-dev
# Optional PKCS#11 support: uncomment to enable --ks-type PKCS11.
# $SUDO apt-get install -y libp11-dev

# --- Decide whether we even need to build PoDoFo from source ----------------
# If a >= 0.10 PoDoFo cmake package is already discoverable, skip the build.
need_podofo_build=1
if pkg-config --atleast-version=0.10 libpodofo 2>/dev/null; then
  echo "    system PoDoFo $(pkg-config --modversion libpodofo) is >= 0.10 — using it"
  need_podofo_build=0
fi

if [ "$need_podofo_build" -eq 1 ]; then
  echo "==> [2/5] Build PoDoFo 0.10 from source (system pkg is too old / absent)"
  if [ ! -d "$PODOFO_SRC/.git" ]; then
    rm -rf "$PODOFO_SRC"
    git clone https://github.com/podofo/podofo.git "$PODOFO_SRC"
  fi
  cd "$PODOFO_SRC"
  git fetch --tags --force
  # Pick the newest 0.10.x release tag.
  PODOFO_TAG="$(git tag -l '0.10.*' | sort -V | tail -1)"
  if [ -z "$PODOFO_TAG" ]; then
    echo "!! could not find a 0.10.* tag; falling back to the master branch"
    git checkout master
  else
    echo "    checking out PoDoFo $PODOFO_TAG"
    git checkout "$PODOFO_TAG"
  fi
  rm -rf build
  cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PODOFO_PREFIX" \
    -DPODOFO_BUILD_STATIC=OFF \
    -DPODOFO_BUILD_TEST=OFF
  cmake --build build -j"$JOBS"
  $SUDO cmake --install build
  $SUDO ldconfig
else
  echo "==> [2/5] Skipping PoDoFo source build (system PoDoFo is new enough)"
fi

echo "==> [3/5] Configure ccpsignpdf against PoDoFo (FRESH build dir)"
# A fresh build dir is essential: a stale CMakeCache from an earlier configure
# is what made CMake ignore toolchain/prefix vars ("Manually-specified variables
# were not used") and silently fall back to the wrong PoDoFo last time.
cd "$HERE"
rm -rf build
cmake -S "$HERE" -B "$HERE/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PODOFO_PREFIX" \
  -Dpodofo_DIR="$PODOFO_PREFIX/lib/cmake/podofo"

echo "==> [4/5] Build ccpsignpdf"
cmake --build "$HERE/build" -j"$JOBS"

echo "==> [5/5] Done"
BIN="$HERE/build/ccpsignpdf"
echo "    binary: $BIN"
# PoDoFo was installed to $PODOFO_PREFIX; if that's not a default loader path,
# the binary needs it at runtime. On most systems ldconfig above handles it.
echo "    if you see 'libpodofo.so not found' at runtime, run:"
echo "        export LD_LIBRARY_PATH=$PODOFO_PREFIX/lib:\$LD_LIBRARY_PATH"
echo
"$BIN" --version || true
