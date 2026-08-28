#!/usr/bin/env bash
# build-buildroot.sh — build the i386 Linux guest image for the v86 track.
#
# Produces:
#   artifacts/bzImage          kernel (kprobes on, KASLR off)
#   artifacts/rootfs.cpio      busybox + gcc + gdbserver + lab overlay (initrd)
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

# Buildroot defconfig for i386 guest: real gcc + gdbserver inside the target,
# serial getty on ttyS0, and the lab overlay merged via BR2_ROOTFS_OVERLAY.
# NOTE: BR2_TOOLCHAIN_* and BR2_USE_WCHAR are toolchain options. If you
# toggle them you MUST wipe the stale toolchain or the cross g++ will stay
# broken (C++11 probe will keep failing with " -h std=c++0x " on the old
# i686-buildroot-linux-gnu-g++). The guard below auto-detects the flip and
# cleans `output/` so a subsequent `make` rebuilds the toolchain.
OLD_CXX="$(grep -E '^BR2_TOOLCHAIN_BUILDROOT_CXX=y' .config 2>/dev/null || echo none)"
OLD_WCHAR="$(grep -E '^BR2_TOOLCHAIN_BUILDROOT_WCHAR=y' .config 2>/dev/null || echo none)"
OLD_USE_WCHAR="$(grep -E '^BR2_USE_WCHAR=y' .config 2>/dev/null || echo none)"

cat > .config <<CFG
BR2_i386=y
BR2_x86_pentium4=y
BR2_TOOLCHAIN_BUILDROOT_GLIBC=y
BR2_TOOLCHAIN_BUILDROOT_CXX=y
BR2_TOOLCHAIN_BUILDROOT_WCHAR=y
BR2_USE_WCHAR=y
BR2_LINUX_KERNEL=y
BR2_LINUX_KERNEL_CUSTOM_VERSION=y
BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="6.6.18"
BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y
BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE="/work/kernel-config"
BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="/work/kernel.fragment"
BR2_TARGET_ROOTFS_CPIO=y
BR2_TARGET_ROOTFS_CPIO_FULL=y
BR2_ROOTFS_OVERLAY="/work/overlay"
BR2_TARGET_GENERIC_GETTY=y
BR2_TARGET_GENERIC_GETTY_PORT="ttyS0"
BR2_TARGET_GENERIC_GETTY_BAUDRATE_115200=y
# Autologin root so the browser console is immediately usable (no `root` prompt).
# The session's waitForShell also handles the classic login prompt, so this is
# an optimization — labs still work if the option is dropped by olddefconfig.
BR2_TARGET_GENERIC_GETTY_AUTOLOGIN="root"
BR2_PACKAGE_BUSYBOX=y
BR2_PACKAGE_GDB=y
BR2_PACKAGE_GDB_SERVER=y
BR2_PACKAGE_GCC=y
BR2_PACKAGE_MAKE=y
BR2_PACKAGE_KMOD=y
BR2_PACKAGE_OPENSSL=y
BR2_PACKAGE_COREUTILS=y
CFG

NEW_CXX="$(grep -E '^BR2_TOOLCHAIN_BUILDROOT_CXX=y' .config 2>/dev/null || echo none)"
NEW_WCHAR="$(grep -E '^BR2_TOOLCHAIN_BUILDROOT_WCHAR=y' .config 2>/dev/null || echo none)"
NEW_USE_WCHAR="$(grep -E '^BR2_USE_WCHAR=y' .config 2>/dev/null || echo none)"
if { [ "$OLD_CXX" != "$NEW_CXX" ] || [ "$OLD_WCHAR" != "$NEW_WCHAR" ] || [ "$OLD_USE_WCHAR" != "$NEW_USE_WCHAR" ]; } && [ -d output/host ]; then
  echo "[v86-lab] toolchain option changed (CXX $OLD_CXX -> $NEW_CXX, WCHAR $OLD_WCHAR -> $NEW_WCHAR, USE_WCHAR $OLD_USE_WCHAR -> $NEW_USE_WCHAR) — cleaning stale output/host"
  echo "[v86-lab] this will rebuild the i686 toolchain (~10-15 min, one-time)"
  make clean 2>/dev/null || rm -rf output
fi
# Additional guard: CXX is enabled but cross g++ is missing (stale toolchain
# from a build that had no CXX). This happens after the first 1A enablement
# where .config already has CXX=y but output/host was built without it.
if grep -q '^BR2_TOOLCHAIN_BUILDROOT_CXX=y' .config && [ ! -f output/host/bin/i686-buildroot-linux-gnu-g++ ] && [ ! -f output/host/bin/i686-buildroot-linux-gnu-g++.br_real ]; then
  echo "[v86-lab] CXX=y but cross g++ missing — stale toolchain, cleaning output"
  make clean 2>/dev/null || rm -rf output
fi

make olddefconfig

# If olddefconfig dropped GDB due to missing C++ deps, re-assert and re-olddefconfig
if ! grep -q '^BR2_PACKAGE_GDB=y' .config; then
  echo "[v86-lab] warning: olddefconfig dropped BR2_PACKAGE_GDB (missing deps) — check CXX/WCHAR"
fi
if ! grep -q '^BR2_PACKAGE_GDB_SERVER=y' .config; then
  echo "[v86-lab] warning: olddefconfig dropped BR2_PACKAGE_GDB_SERVER"
fi

set +e
make -j"$(nproc)" BR2_DOWNLOAD_VERIFY_CHECKS=n FORCE_UNSAFE_CONFIGURE=1
STATUS=$?
set -e
if [ $STATUS -ne 0 ]; then
  echo ""
  echo "[v86-lab] *** build failed (see gdbserver C++11 probe above) ***"
  echo "[v86-lab] 1A (current): BR2_PACKAGE_GDB + BR2_PACKAGE_GDB_SERVER + CXX+WCHAR"
  echo "[v86-lab] If the probe keeps failing with \"-h std=c++0x\", this is the"
  echo "[v86-lab] stale-toolchain case. Recovery:"
  echo "[v86-lab]   docker volume rm $VOL   # wipes the i686 toolchain (one-time, ~10-15 min rebuild)"
  echo "[v86-lab]   ./packages/v86-lab/scripts/build-buildroot.sh   # retry"
  echo "[v86-lab] Fallbacks (if recovery still fails):"
  echo "[v86-lab]   1B: edit this script to drop BR2_PACKAGE_GDB (keep only BR2_PACKAGE_GDB_SERVER)"
  echo "[v86-lab]   1C: drop both GDB lines and ship a prebuilt static gdbserver via overlay/usr/bin/gdbserver"
  echo ""
  exit $STATUS
fi

# Stage kernel headers for in-guest `gcc -I/lib/modules/$(uname -r)/build/include`
# The student modules compile with `gcc -O2 -c -I/lib/modules/$(uname -r)/build/include
# -I/lib/modules/$(uname -r)/build/arch/x86/include -D__KERNEL__` (see
# apps/web/src/lkm-builder.mjs). Without these headers that gcc line fails with
# "linux/module.h: No such file".
KDIR="$(ls -d output/build/linux-* 2>/dev/null | head -n1 || true)"
if [ -n "$KDIR" ] && [ -d "$KDIR/include" ]; then
  KVER="$(cat "$KDIR/include/config/kernel.release" 2>/dev/null || echo "6.6.18")"
  echo "[v86-lab] staging kernel headers for \$KVER=$KVER from $KDIR"
  mkdir -p "target/lib/modules/$KVER/build"
  # minimal header set needed for -c builds (full copy would be ~200MB; keep it lean)
  mkdir -p "target/lib/modules/$KVER/build/include"
  cp -r "$KDIR/include" "target/lib/modules/$KVER/build/" 2>/dev/null || true
  if [ -d "$KDIR/arch/x86/include" ]; then
    mkdir -p "target/lib/modules/$KVER/build/arch/x86"
    cp -r "$KDIR/arch/x86/include" "target/lib/modules/$KVER/build/arch/x86/" 2>/dev/null || true
  fi
  # Also ensure the arch symlink buildroot's KDIR expects
  mkdir -p "target/lib/modules/$KVER/build/arch"
  # Rebuild cpio so the staged headers are included
  make -j"$(nproc)" BR2_DOWNLOAD_VERIFY_CHECKS=n FORCE_UNSAFE_CONFIGURE=1 || true
else
  echo "[v86-lab] warning: could not locate linux build dir for header staging (KDIR=$KDIR)"
fi

# Ensure the 9p file injection target exists at boot (create_file needs parent dirs)
mkdir -p target/root/lab

# List what made it into the image (debug aid)
echo "[v86-lab] overlay + image contents:"
ls -R /work/overlay 2>/dev/null | head -n 80 || true
ls -lh output/images/bzImage output/images/rootfs.cpio 2>/dev/null || true
ls -lh target/root/lab/ 2>/dev/null | head -n 40 || true
which gdbserver 2>/dev/null || echo "note: host gdbserver not relevant; checking target"
ls -lh target/usr/bin/gdbserver 2>/dev/null || echo "target gdbserver missing — check BR2_PACKAGE_GDB_SERVER"
ls -lh target/usr/bin/gcc 2>/dev/null || echo "target gcc missing — check BR2_PACKAGE_GDB/GCC"
EOS

echo "[v86-lab] copying kernel + initrd out of the volume"
docker run --rm -v "$VOL":/work:ro -v "$PWD/$ART":/out "$IMAGE" \
  cp /work/buildroot/output/images/bzImage /work/buildroot/output/images/rootfs.cpio /out/

ls -la "$ART/"
echo "done."
