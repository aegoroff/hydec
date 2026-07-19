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
Usage: build-apk.sh --bin PATH --arch ARCH --version VERSION [options]

Required:
  --bin PATH         Path to stripped hydec binary (static musl)
  --arch ARCH        OpenWrt package arch (e.g. x86_64, aarch64_generic)
  --version VERSION  APK version (e.g. 0.1.0-r1). Use -rN release suffix.

Options:
  --out DIR          Output directory (default: zig-out/apk)
  --name NAME        Package name (default: hydec)
  -h, --help         Show this help

Requires: apk-tools 3.x (apk mkpkg), fakeroot

Example:
  ./packaging/openwrt-apk/build-apk.sh \
    --bin zig-out/bin-x86_64-linux-musl/hydec \
    --arch x86_64 \
    --version 0.1.0-r1
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

# Map hydec -Dversion strings to apk-tools-valid versions.
# 0.1.0-dev -> 0.1.0_git0; 0.1.0 -> 0.1.0-r1; already -rN / _gitN kept.
sanitize_apk_version() {
  local v="$1"
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*-r[0-9]+$ ]]; then
    printf '%s\n' "$v"
    return
  fi
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*_git[0-9]+$ ]]; then
    printf '%s\n' "$v"
    return
  fi
  if [[ "$v" == *-dev ]]; then
    printf '%s_git0\n' "${v%-dev}"
    return
  fi
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    printf '%s-r1\n' "$v"
    return
  fi
  die "version '$v' is not apk-valid; use e.g. 0.1.0-r1 or 0.1.0_git0"
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

mkdir -p "$OUT_DIR"
OUT_APK="$OUT_DIR/${PKG_NAME}-${PKG_VERSION}-${PKG_ARCH}.apk"

# Unsigned package for OpenWrt 25.12+; install with:
#   apk add --allow-untrusted ./hydec-….apk
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
