# OpenWrt 25.12+ `.apk` (MVP)

SDK-free packaging: cross-compile static musl `hydec`, wrap with `apk mkpkg`.

## Prerequisites

- Zig 0.16 (mise) + `just`
- `apk-tools` 3.x (`apk mkpkg`) — e.g. `pacman -S apk-tools`
- `fakeroot` — for `root:root` ownership inside the package

## Build

Any `ver=` is sanitized to `X.Y.Z-rN` before compile/package. Only that form
is shipped. `_git*` is never produced; unsanitizable inputs fail the build.

| Input `ver=` | Artifact version |
|--------------|------------------|
| `0.1.0` | `0.1.0-r1` |
| `0.1.0-dev` | `0.1.0-r1` |
| `0.1.0-r2` | `0.1.0-r2` (unchanged) |

```bash
# x86_64 + aarch64_cortex-a53 + aarch64_generic → zig-out/apk/
just ver=0.1.0 openwrt-apk

# one arch
just ver=0.1.0 zig_arch=x86_64 openwrt_arch=x86_64 openwrt-apk-one
just ver=0.1.0 zig_arch=aarch64 openwrt_arch=aarch64_cortex-a53 openwrt-apk-one
just ver=0.1.0 zig_arch=aarch64 openwrt_arch=aarch64_generic openwrt-apk-one
```

## Install on device

Match the `.apk` to `cat /etc/apk/arch` on the router (usually `aarch64_cortex-a53`):

```bash
scp zig-out/apk/hydec-0.1.0-r1-aarch64_cortex-a53.apk root@router:/tmp/
# If a previous failed apk add left a broken world pin:
#   grep hydec /etc/apk/world && sed -i '/^hydec/d' /etc/apk/world
ssh root@router 'apk add --allow-untrusted /tmp/hydec-0.1.0-r1-aarch64_cortex-a53.apk'
hydec -V
```

Unsigned on purpose for MVP. Needs `ca-bundle` (declared as a package dependency) for HTTPS / Trojan TLS.

## Arch note

Package `arch` must equal a line in `/etc/apk/arch` on the device. `just openwrt-apk` ships both `aarch64_cortex-a53` and `aarch64_generic` (same aarch64 musl binary). `--arch` on `apk add` does **not** make a foreign-arch package installable.
