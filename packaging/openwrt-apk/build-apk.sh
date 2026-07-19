#!/usr/bin/env bash
# Build an unsigned OpenWrt 25.12+ .apk for hydec (SDK-free).
# Requires apk-tools 3.x on PATH (`apk mkpkg`) and fakeroot for root:root ownership.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/zig-out/apk}"

PKG_NAME="hydec"
PKG_VERSION=""
PKG_ARCH=""
BIN_PATH=""
MAINTAINER="${MAINTAINER:-hydec contributors}"
URL="${URL:-https://git.egoroff.spb.ru/egr/hydec}"

usage() {
  cat <<'EOF'
Usage:
  build-apk.sh --bin PATH --arch ARCH --version VERSION [options]
  build-apk.sh --sanitize-version VERSION

Any --version is accepted if it can be rewritten to X.Y.Z-rN; only that
sanitized form is compiled into the binary and written into the .apk.
Inputs that cannot become -rN are rejected (no _git* packages).

  0.1.0-dev  -> 0.1.0-r1
  0.1.0      -> 0.1.0-r1
  0.1.0-r2   -> 0.1.0-r2 (unchanged)
  weird-tag  -> error (do not build)

Required (package mode):
  --bin PATH         Path to stripped hydec binary (static musl)
  --arch ARCH        OpenWrt package arch (e.g. x86_64, aarch64_generic)
  --version VERSION  Input version (sanitized before packaging)

Options:
  --out DIR          Output directory (default: zig-out/apk)
  --name NAME        Package name (default: hydec)
  --sanitize-version VERSION
                     Print sanitized apk version and exit
  -h, --help         Show this help

Requires: apk-tools 3.x (apk mkpkg), fakeroot

Example:
  ./packaging/openwrt-apk/build-apk.sh \
    --bin zig-out/bin-x86_64-linux-musl/hydec \
    --arch x86_64 \
    --version 0.1.0
  # → zig-out/apk/x86_64/hydec-0.1.0-r1.apk
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

# Map hydec version strings to apk-valid OpenWrt release form (X.Y.Z-rN only).
# Never emits _git*; if the input cannot become -rN, fail (do not package).
sanitize_apk_version() {
  local v="$1"
  if [[ -z "$v" ]]; then
    die "empty version"
  fi
  # Already release-shaped.
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*-r[0-9]+$ ]]; then
    printf '%s\n' "$v"
    return
  fi
  # Strip -dev / _gitN noise, then require a plain numeric version.
  v="${v%-dev}"
  v="${v%%_git*}"
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    printf '%s-r1\n' "$v"
    return
  fi
  die "version '$1' cannot be sanitized to X.Y.Z-rN (refusing to build)"
}

resolve_apk() {
  local bin="${APK:-apk}"
  local ver
  if ! command -v "$bin" >/dev/null 2>&1; then
    die "'$bin' not found; install apk-tools 3.x (e.g. pacman -S apk-tools) or set APK="
  fi
  ver="$("$bin" --version 2>&1 || true)"
  if [[ "$ver" != apk-tools\ 3.* ]]; then
    die "'$bin' is not apk-tools 3.x (got: ${ver:-unknown})"
  fi
  command -v "$bin"
}

if [[ "${1:-}" == "--sanitize-version" ]]; then
  [[ -n "${2:-}" ]] || die "--sanitize-version requires a VERSION"
  sanitize_apk_version "$2"
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      BIN_PATH="${2:-}"
      shift 2
      ;;
    --arch)
      PKG_ARCH="${2:-}"
      shift 2
      ;;
    --version)
      PKG_VERSION="${2:-}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --name)
      PKG_NAME="${2:-}"
      shift 2
      ;;
    --sanitize-version)
      die "--sanitize-version must be the first argument"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$BIN_PATH" ]] || die "--bin is required"
[[ -n "$PKG_ARCH" ]] || die "--arch is required"
[[ -n "$PKG_VERSION" ]] || die "--version is required"
[[ -f "$BIN_PATH" ]] || die "binary not found: $BIN_PATH"
[[ -x "$BIN_PATH" ]] || die "binary not executable: $BIN_PATH"
command -v fakeroot >/dev/null 2>&1 || die "fakeroot not found (needed for root:root package ownership)"

PKG_VERSION="$(sanitize_apk_version "$PKG_VERSION")"
APK_BIN="$(resolve_apk)"

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

ROOTFS="$WORKDIR/root"
mkdir -p "$ROOTFS/usr/bin"
install -m 0755 "$BIN_PATH" "$ROOTFS/usr/bin/hydec"

mkdir -p "$OUT_DIR/$PKG_ARCH"
# OpenWrt Image Builder indexes by name-version.apk only (no arch in filename).
# See https://github.com/openwrt/openwrt/issues/23154
OUT_APK="$OUT_DIR/$PKG_ARCH/${PKG_NAME}-${PKG_VERSION}.apk"

# Unsigned package for OpenWrt 25.12+; install with:
#   apk add --allow-untrusted ./hydec-….apk
# Image Builder: file must be named name-version.apk (no arch in filename).
# ca-bundle: system trust store for HTTPS subscription fetch / Trojan TLS.
export APK_BIN ROOTFS OUT_APK PKG_NAME PKG_VERSION PKG_ARCH URL MAINTAINER
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

mkpkg_body() {
  chown -R root:root "$ROOTFS"
  "$APK_BIN" mkpkg \
    --info "name:${PKG_NAME}" \
    --info "version:${PKG_VERSION}" \
    --info "description:Probe proxy subscription and print the fastest working node" \
    --info "arch:${PKG_ARCH}" \
    --info "license:MIT" \
    --info "origin:hydec" \
    --info "url:${URL}" \
    --info "maintainer:${MAINTAINER}" \
    --info "depends:ca-bundle" \
    --files "$ROOTFS" \
    --output "$OUT_APK"
}

fakeroot -- bash -c "$(declare -f mkpkg_body); mkpkg_body"

"$APK_BIN" adbdump "$OUT_APK" >/dev/null \
  || die "apk adbdump failed — package may be corrupt: $OUT_APK"

echo "wrote $OUT_APK ($(wc -c <"$OUT_APK") bytes)"
