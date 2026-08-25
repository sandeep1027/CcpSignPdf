#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-portable.sh — produce a portable Linux ccpsignpdf.
#
# Statically links PoDoFo, OpenSSL, libcurl, libstdc++ and libgcc. glibc stays
# DYNAMIC so TSA/OCSP/CRL hostname lookups via NSS still work.
#
# The resulting binary runs on glibc >= the build host (Ubuntu 22.04 => 2.35)
# without needing PoDoFo/OpenSSL/curl installed there.
#
# Re-runnable. No root required. Intermediate deps live in .deps/.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS="${DEPS:-$HERE/.deps}"
PREFIX="$DEPS/prefix"
PODOFO_SRC="${PODOFO_SRC:-$HOME/podofo-src}"
CURL_VER="${CURL_VER:-8.11.1}"
JOBS="$(nproc 2>/dev/null || echo 2)"
BUILD_DIR="$HERE/build-portable"

mkdir -p "$DEPS/src" "$PREFIX"

# Prefer static archives for every find_library() in the dep builds.
STATIC_CMAKE=(
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX="$PREFIX"
  -DBUILD_SHARED_LIBS=OFF
  -DCMAKE_FIND_LIBRARY_SUFFIXES=.a
  -DOPENSSL_USE_STATIC_LIBS=ON
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
)

echo "==> [1/4] Minimal static libcurl $CURL_VER (no GSSAPI/LDAP/SSH/HTTP2)"
CURL_SRC="$DEPS/src/curl-$CURL_VER"
if [ ! -f "$PREFIX/lib/libcurl.a" ]; then
  if [ ! -d "$CURL_SRC" ]; then
    tarball="$DEPS/src/curl-$CURL_VER.tar.gz"
    if [ ! -f "$tarball" ]; then
      url="https://curl.se/download/curl-$CURL_VER.tar.gz"
      echo "    downloading $url"
      curl -fsSL "$url" -o "$tarball"
    fi
    tar -xzf "$tarball" -C "$DEPS/src"
  fi
  rm -rf "$DEPS/src/curl-build"
  cmake -S "$CURL_SRC" -B "$DEPS/src/curl-build" \
    "${STATIC_CMAKE[@]}" \
    -DBUILD_CURL_EXE=OFF \
    -DCURL_USE_OPENSSL=ON \
    -DCURL_USE_LIBPSL=OFF \
    -DCURL_USE_LIBSSH2=OFF \
    -DUSE_NGHTTP2=OFF \
    -DUSE_LIBIDN2=OFF \
    -DCURL_BROTLI=OFF \
    -DCURL_ZSTD=OFF \
    -DCURL_DISABLE_LDAP=ON \
    -DCURL_DISABLE_LDAPS=ON
  cmake --build "$DEPS/src/curl-build" -j"$JOBS"
  cmake --install "$DEPS/src/curl-build"
else
  echo "    using existing $PREFIX/lib/libcurl.a"
fi

echo "==> [2/4] Static PoDoFo 0.10 (PNG/JPEG, no TIFF — missing static libwebp/zstd)"
if [ ! -d "$PODOFO_SRC/.git" ] && [ ! -f "$PODOFO_SRC/CMakeLists.txt" ]; then
  echo "    cloning PoDoFo into $PODOFO_SRC"
  git clone --depth 1 --branch 0.10.6 https://github.com/podofo/podofo.git "$PODOFO_SRC"
fi
if [ ! -f "$PREFIX/lib/libpodofo.a" ]; then
  rm -rf "$DEPS/src/podofo-build"
  cmake -S "$PODOFO_SRC" -B "$DEPS/src/podofo-build" \
    "${STATIC_CMAKE[@]}" \
    -DPODOFO_BUILD_STATIC=ON \
    -DPODOFO_BUILD_TEST=OFF \
    -DPODOFO_BUILD_EXAMPLES=OFF \
    -DPODOFO_BUILD_TOOLS=OFF \
    -DCMAKE_DISABLE_FIND_PACKAGE_TIFF=TRUE \
    -DCMAKE_PREFIX_PATH="$PREFIX"
  cmake --build "$DEPS/src/podofo-build" -j"$JOBS"
  cmake --install "$DEPS/src/podofo-build"
else
  echo "    using existing $PREFIX/lib/libpodofo.a"
fi

echo "==> [3/4] Configure + build ccpsignpdf (BUILD_STATIC=ON)"
rm -rf "$BUILD_DIR"
cmake -S "$HERE" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_STATIC=ON \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
  -Dpodofo_DIR="$PREFIX/share/podofo" \
  -DCMAKE_FIND_LIBRARY_SUFFIXES=.a \
  -DOPENSSL_USE_STATIC_LIBS=ON \
  -DCURL_USE_STATIC_LIBS=ON \
  -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++"
cmake --build "$BUILD_DIR" -j"$JOBS"

BIN="$BUILD_DIR/ccpsignpdf"
strip "$BIN" 2>/dev/null || true
echo
echo "==> [4/4] Done: $BIN"
echo "    size: $(du -h "$BIN" | awk '{print $1}')"
echo "    runtime deps (expect only glibc-family: libc, libm, ld-linux):"
ldd "$BIN" || true
echo
"$BIN" --version || true
