# OpenWrt 25.12+ `.apk` (MVP)

SDK-free packaging: cross-compile static musl `hydec`, wrap with `apk mkpkg`.

## Prerequisites

- Zig 0.16 ([mise](https://mise.jdx.dev/) pin in repo `mise.toml`) + `just`
- **apk-tools 3.x** with `apk mkpkg` (OpenWrt 25.12 uses APKv3 — apk 2.x will not work)
- `fakeroot` — for `root:root` ownership inside the package

Check:

```bash
apk --version          # expect: apk-tools 3.x
apk mkpkg --help       # applet must exist (exit code may be non-zero; look for Usage: apk mkpkg)
command -v fakeroot
```

### Install host tools by distro

Need **apk-tools ≥ 3.0** (with `mkpkg`). Status as of mid‑2026 — check `apk --version` after install.

| Distro | Commands | Notes |
|--------|----------|--------|
| **Arch / Manjaro** | `sudo pacman -S apk-tools fakeroot` | 3.x in `extra` |
| **Fedora** (42+) | `sudo dnf install apk-tools fakeroot` | 3.x in updates; older Fedora may still be 2.x |
| **openSUSE Tumbleweed** | `sudo zypper install apk-tools fakeroot` | 3.x |
| **Alpine** (3.23+ / edge) | already has `apk`; `sudo apk add fakeroot` | older Alpine branches ship apk **2.x** — not enough |
| **Nix / NixOS** | `nix shell nixpkgs#apk-tools nixpkgs#fakeroot` | prefer recent nixpkgs (3.x); or add to system packages |
| **Chimera** | `doas apk add apk-tools fakeroot` | 3.x |

**Debian / Ubuntu / Mint / Void** — no usable apk **3.x** in the default repos (Void still has 2.x). Use one of:

1. **Nix** (simplest if you already use it):

   ```bash
   nix shell nixpkgs#apk-tools nixpkgs#fakeroot
   ```

2. **Build from source** (Debian/Ubuntu example):

   ```bash
   sudo apt install meson ninja-build pkg-config libssl-dev zlib1g-dev fakeroot
   git clone --depth 1 --branch v3.0.6 https://gitlab.alpinelinux.org/alpine/apk-tools.git
   cd apk-tools
   meson setup build -Dprefix=/usr/local
   meson compile -C build
   sudo meson install -C build
   ```

3. Package on a host that already has apk 3.x (Arch, Fedora 42+, Alpine 3.23+), or only for the `apk mkpkg` step.

Optional override if `apk` is not on `PATH`:

```bash
export APK=/path/to/apk
```

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
