#!/usr/bin/env bash
# build-buildroot.sh — build the i386 Linux guest image for the v86 track.
#
# Produces:
#   artifacts/bzImage          kernel (kprobes on, KASLR off)
#   artifacts/rootfs.ext2      busybox + lab overlay
#
# Strategy: ALL building happens inside a named docker volume (native Linux
# fs). Bind-mounting the macOS filesystem breaks kernel-source extraction —
# the tree contains symlinks (powerpc selftests -> arch/powerpc) that Docker
# Desktop's bind mount cannot recreate, failing with "Permission denied".
# Only the final bzImage/rootfs are copied out to artifacts/.
#
# Host notes:
#  - amd64-emulated images segfault gcc under Rosetta; use a NATIVE arm64
#    image (ubuntu:24.04) — buildroot cross-compiles i386 anyway.
#  - ghcr.io/buildroot/buildroot is registry-denied; buildroot/base lacks a
#    buildroot tree. ubuntu:24.04 + apt deps works.
set -euo pipefail

cd "$(dirname "$0")/.."
ART=artifacts
BUILDROOT_VER=2024.02
VOL=kf-buildroot-vol
mkdir -p "$ART"

IMAGE="${BUILDROOT_IMAGE:-ubuntu:24.04}"

# seed the volume with buildroot sources + our overlay/fragment (once)
docker volume create "$VOL" > /dev/null
docker run -i --rm -v "$VOL":/work -v "$PWD":/seed:ro \
  -e BUILDROOT_VER="$BUILDROOT_VER" "$IMAGE" bash -s <<'EOS'
set -euo pipefail
if [ ! -f /work/buildroot/Makefile ]; then
  rm -rf /work/buildroot /work/buildroot-2024.02
  apt-get update -qq && apt-get install -y -qq curl xz-utils ca-certificates > /dev/null
  # download to file first: piping curl|tar truncates the stream here
  curl -sL "https://buildroot.org/downloads/buildroot-$BUILDROOT_VER.tar.gz" -o /work/br.tar.gz
  tar -xzf /work/br.tar.gz -C /work
  mv /work/buildroot-$BUILDROOT_VER /work/buildroot
  rm /work/br.tar.gz
fi
mkdir -p /work/overlay
cp -r /seed/overlay/. /work/overlay/
cp /seed/kernel.fragment /work/
test -f /work/buildroot/Makefile   # hard gate: seeding actually worked
EOS

echo "[v86-lab] building i386 buildroot guest ($IMAGE, in-volume)…"

docker run -i --rm -v "$VOL":/work -w /work/buildroot "$IMAGE" bash -s <<'EOS'
set -euo pipefail
apt-get update -qq && apt-get install -y -qq \
  build-essential cpio rsync bc wget file unzip xz-utils \
  libssl-dev libelf-dev openssl > /dev/null
ulimit -c 0

cat > .config <<CFG
BR2_i386=y
BR2_x86_pentium4=y
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.6.18"
BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="/work/kernel-config"
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="/work/kernel.fragment"
BR2_TARGET_ROOTFS_EXT2=y
CFG

make olddefconfig
make -j"$(nproc)" BR2_DOWNLOAD_VERIFY_CHECKS=n FORCE_UNSAFE_CONFIGURE=1

mkdir -p target/root/lab
cp -r /work/overlay/* target/root/lab/
EOS

echo "[v86-lab] copying kernel + rootfs out of the volume"
docker run --rm -v "$VOL":/work:ro -v "$PWD/$ART":/out "$IMAGE" \
  cp /work/buildroot/output/images/bzImage /work/buildroot/output/images/rootfs.ext2 /out/

ls -la "$ART/"
echo "done."
