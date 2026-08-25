#!/usr/bin/env bash
# build-buildroot.sh — build the i386 Linux guest image for the v86 track.
#
# Produces:
#   artifacts/bzImage          kernel (kprobes on, KASLR off)
#   artifacts/rootfs.ext2      busybox + gcc + lab overlay
#
# Boot-state snapshot for fast student boots is saved separately
# (scripts/save-boot-state.mjs) after first boot.
#
# Requirements: docker (or podman), ~20 min first build.
set -euo pipefail

cd "$(dirname "$0")/.."
ART=artifacts
OVERLAY=overlay
mkdir -p "$ART"

IMAGE="${BUILDROOT_IMAGE:-ghcr.io/buildroot/buildroot:2024.02}"

echo "[v86-lab] building i386 buildroot guest with $IMAGE (this takes a while)…"

docker run --rm -v "$PWD":/lab -w /lab "$IMAGE" bash -s <<'EOS'
set -euo pipefail

cat > .config <<CFG
BR2_i386=y
BR2_x86_pentium4=y
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.6.18"
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="/lab/kernel.fragment"
BR2_TARGET_ROOTFS_EXT2=y
BR2_PACKAGE_GCC=y
BR2_PACKAGE_MAKE=y
CFG

make olddefconfig
make -j"$(nproc)"

mkdir -p target/root/lab
cp -r /lab/overlay/* target/root/lab/
EOS

echo "[v86-lab] copying kernel + rootfs"
cp output/images/bzImage "$ART/"
cp output/images/rootfs.ext2 "$ART/"

echo "done. next: boot once under v86 and save the state snapshot:"
echo "  node scripts/save-boot-state.mjs"
