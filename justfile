optimize := "ReleaseSmall"
default_version := "0.1.0-dev"

# Target overrides (CI / release): just arch=aarch64 os=linux abi=musl ver=0.1.0 release
arch := "x86_64"
os := "linux"
abi := "musl"
ver := default_version
cpu := "core2"

# Local build target (just build / just test)
local_target := "x86_64-linux-musl"
local_cpu := "core2"

zig := "mise exec -- zig"
triple := arch + "-" + os + "-" + abi
prefix := "bin-" + arch + "-" + os + "-" + abi
cpu_flag := if cpu != "" { "-Dcpu=" + cpu } else { "" }

# Local ReleaseFast build (x86_64-linux-musl / core2)
build:
    {{ zig }} build -Doptimize={{ optimize }} -Dtarget={{ local_target }} -Dcpu={{ local_cpu }} -Dversion={{ ver }} --summary all

# Local unit tests for the default target
test:
    {{ zig }} build test -Doptimize={{ optimize }} -Dtarget={{ local_target }} -Dcpu={{ local_cpu }} -Dversion={{ ver }} --summary all

# Build + archive one target; runs tests for x86_64-linux
# Example: just arch=x86_64 os=linux abi=musl ver=0.1.0 cpu=core2 release
release: maybe-test archive-target

[private]
build-target:
    {{ zig }} build \
        -Doptimize={{ optimize }} \
        {{ cpu_flag }} \
        -Dtarget={{ triple }} \
        -Dversion={{ ver }} \
        --summary all \
        --prefix-exe-dir {{ prefix }}

[private]
maybe-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "{{ arch }}" == "x86_64" && "{{ os }}" == "linux" ]]; then
      {{ zig }} build test \
        -Doptimize={{ optimize }} \
        {{ cpu_flag }} \
        -Dtarget={{ triple }} \
        --summary all
    fi

[private]
archive-target:
    {{ zig }} build archive \
        -Doptimize={{ optimize }} \
        {{ cpu_flag }} \
        -Dtarget={{ triple }} \
        -Dversion={{ ver }} \
        --summary all \
        --prefix-exe-dir {{ prefix }}

# Cross-build all CI release targets (just ver=0.1.0 build-all)
build-all:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f ./zig-out/*.tar.gz
    rm -rf ./zig-out/bin-*
    just arch=x86_64 os=linux abi=musl ver={{ ver }} optimize={{ optimize }} cpu=core2 release
    just arch=aarch64 os=linux abi=musl ver={{ ver }} optimize={{ optimize }} cpu= release
    just arch=x86_64 os=macos abi=none ver={{ ver }} optimize={{ optimize }} cpu=core2 release
    just arch=aarch64 os=macos abi=none ver={{ ver }} optimize={{ optimize }} cpu=apple_m1 release
    just arch=x86_64 os=windows abi=gnu ver={{ ver }} optimize={{ optimize }} cpu=core2 release
