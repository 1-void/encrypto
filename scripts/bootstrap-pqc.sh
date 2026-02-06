#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQC_DIR="${PQC_DIR:-$ROOT/.pqc}"
SRC_DIR="$PQC_DIR/src"
BUILD_DIR="$PQC_DIR/build"

OPENSSL_TAG="${OPENSSL_TAG:-openssl-3.5.5}"
LIBOQS_TAG="${LIBOQS_TAG:-0.15.0}"
OQSPROVIDER_TAG="${OQSPROVIDER_TAG:-0.10.0}"
OPENSSL_COMMIT="${OPENSSL_COMMIT:-}"
LIBOQS_COMMIT="${LIBOQS_COMMIT:-}"
OQSPROVIDER_COMMIT="${OQSPROVIDER_COMMIT:-}"
PQC_VERIFY="${PQC_VERIFY:-0}"

PQC_WITH_OQS="${PQC_WITH_OQS:-0}"

OPENSSL_PREFIX="$PQC_DIR/openssl"
OQS_PREFIX="$PQC_DIR/oqs"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

require_cmd git
require_cmd cmake
require_cmd make
require_cmd perl
require_cmd gcc

mkdir -p "$SRC_DIR" "$BUILD_DIR"

verify_commit() {
  local dir="$1"
  local expected="$2"
  local name="$3"
  if [[ -n "$expected" ]]; then
    local actual
    actual="$(git -C "$dir" rev-parse HEAD)"
    if [[ "$actual" != "$expected" ]]; then
      echo "error: $name commit mismatch ($actual != $expected)" >&2
      exit 1
    fi
  elif [[ "$PQC_VERIFY" == "1" ]]; then
    echo "error: PQC_VERIFY=1 requires ${name}_COMMIT to be set" >&2
    exit 1
  fi
}

clone_or_update() {
  local url="$1"
  local dir="$2"
  local ref="$3"
  local commit="$4"
  local name="$5"
  if [[ -d "$dir/.git" ]]; then
    if [[ "${PQC_UPDATE:-0}" == "1" ]]; then
      git -C "$dir" fetch --tags --force
      git -C "$dir" checkout -q "$ref"
      git -C "$dir" pull --ff-only
    else
      echo "using existing repo: $dir"
    fi
  else
    git clone --depth 1 --branch "$ref" "$url" "$dir"
  fi
  # If an exact commit is provided, prefer checking it out explicitly to
  # make builds reproducible even if tags move (or if ref is changed).
  if [[ -n "$commit" ]]; then
    git -C "$dir" fetch --depth 1 origin "$commit" >/dev/null 2>&1 || true
    git -C "$dir" checkout -q "$commit"
  fi
  verify_commit "$dir" "$commit" "$name"
}

echo "==> Fetching sources"
clone_or_update https://github.com/openssl/openssl.git "$SRC_DIR/openssl" "$OPENSSL_TAG" "$OPENSSL_COMMIT" "OPENSSL"
if [[ "$PQC_WITH_OQS" == "1" ]]; then
  clone_or_update https://github.com/open-quantum-safe/liboqs.git "$SRC_DIR/liboqs" "$LIBOQS_TAG" "$LIBOQS_COMMIT" "LIBOQS"
  clone_or_update https://github.com/open-quantum-safe/oqs-provider.git "$SRC_DIR/oqs-provider" "$OQSPROVIDER_TAG" "$OQSPROVIDER_COMMIT" "OQSPROVIDER"
fi

echo "==> Building OpenSSL $OPENSSL_TAG"
pushd "$SRC_DIR/openssl" >/dev/null
# If the source tree was previously configured with a different prefix,
# OpenSSL may keep stale install metadata (e.g. installdata.pm), which
# then poisons the generated pkg-config files. Reset to a clean state.
if [[ -f Makefile ]]; then
  make distclean >/dev/null 2>&1 || true
fi
./Configure --prefix="$OPENSSL_PREFIX" --openssldir="$OPENSSL_PREFIX" shared
make -j"$(nproc)"
make install_sw
popd >/dev/null

OPENSSL_LIBDIR="lib"
if [[ -d "$OPENSSL_PREFIX/lib64" ]]; then
  OPENSSL_LIBDIR="lib64"
fi

if [[ "$PQC_WITH_OQS" == "1" ]]; then
  echo "==> Building liboqs"
  cmake -S "$SRC_DIR/liboqs" -B "$BUILD_DIR/liboqs" \
    -DCMAKE_INSTALL_PREFIX="$OQS_PREFIX" \
    -DBUILD_SHARED_LIBS=ON
  cmake --build "$BUILD_DIR/liboqs" -j"$(nproc)"
  cmake --install "$BUILD_DIR/liboqs"

  echo "==> Building oqs-provider"
  cmake -S "$SRC_DIR/oqs-provider" -B "$BUILD_DIR/oqs-provider" \
    -DCMAKE_INSTALL_PREFIX="$OQS_PREFIX" \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DOPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include" \
    -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_PREFIX/$OPENSSL_LIBDIR/libcrypto.so" \
    -DOPENSSL_SSL_LIBRARY="$OPENSSL_PREFIX/$OPENSSL_LIBDIR/libssl.so" \
    -DOQS_DIR="$OQS_PREFIX"
  cmake --build "$BUILD_DIR/oqs-provider" -j"$(nproc)"
  cmake --install "$BUILD_DIR/oqs-provider"
fi

echo "==> Writing OpenSSL config"
if [[ "$PQC_WITH_OQS" == "1" ]]; then
  cat > "$OPENSSL_PREFIX/openssl.cnf" <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = $OPENSSL_PREFIX/$OPENSSL_LIBDIR/ossl-modules/oqsprovider.so
EOF
else
  cat > "$OPENSSL_PREFIX/openssl.cnf" <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
EOF
fi

echo "==> Writing env helper"
cat > "$ROOT/scripts/pqc-env.sh" <<EOF
export PQC_DIR="$PQC_DIR"
export OPENSSL_DIR="$OPENSSL_PREFIX"
export OPENSSL_CONF="$OPENSSL_PREFIX/openssl.cnf"
export QPGP_OPENSSL_CONF="$OPENSSL_PREFIX/openssl.cnf"
export OPENSSL_MODULES="$OPENSSL_PREFIX/$OPENSSL_LIBDIR/ossl-modules"
export PKG_CONFIG_PATH="$OPENSSL_PREFIX/$OPENSSL_LIBDIR/pkgconfig"
export LD_LIBRARY_PATH="$OPENSSL_PREFIX/$OPENSSL_LIBDIR:$OQS_PREFIX/lib:\${LD_LIBRARY_PATH:-}"
EOF

echo "==> Done"
echo "Pinned revisions:"
echo "  OPENSSL_TAG=$OPENSSL_TAG OPENSSL_COMMIT=$(git -C "$SRC_DIR/openssl" rev-parse HEAD)"
if [[ "$PQC_WITH_OQS" == "1" ]]; then
  echo "  LIBOQS_TAG=$LIBOQS_TAG LIBOQS_COMMIT=$(git -C "$SRC_DIR/liboqs" rev-parse HEAD)"
  echo "  OQSPROVIDER_TAG=$OQSPROVIDER_TAG OQSPROVIDER_COMMIT=$(git -C "$SRC_DIR/oqs-provider" rev-parse HEAD)"
fi
echo "Next:"
echo "  source scripts/pqc-env.sh"
echo "  cargo run -p qpgp-cli -- info"
