#!/bin/sh
# Lab init overlay: spawn decoy victims, seed files, keep console ready.
# Runs from /etc/init.d/S99kflag inside the buildroot guest.

# decoy tasks the villain will hide (count pinned by src/seeds.mjs)
# Use a sh loop that sets comm via /proc/self/comm so kfvillain finds it.
# `exec -a` with busybox applets fails (busybox looks up applet by comm), and
# target has no coreutils sleep, so we keep the parent sh as kfvictim.
for i in 1 2 3; do
  ( echo -n "kfvictim$i" > /proc/self/comm 2>/dev/null; cat /proc/self/comm 2>/dev/null | head -c 20; echo " spawned"; while true; do /bin/sleep 1 2>/dev/null || sleep 1; done ) &
done
# let decoys settle and be visible in task list before villain scans
sleep 1
echo "[lab-init] decoys spawned, ps check:"
ps 2>&1 | head -n 20
ps 2>&1 | grep -c kfvictim || echo "no kfvictim in ps"
cat /proc/self/comm 2>&1 | head

# m7 seed: secret file read from kernel space
echo "kf-lkm-hello" > /root/.kflag

# m8 trigger binary: execve storm for kprobe labs
cat > /root/trigger <<'TRIG'
#!/bin/sh
exit 0
TRIG
chmod +x /root/trigger

# build + load the villains last so they hide the live decoys above
# kfvillain.ko: task-unlinking rootkit (m9) — hide 3 decoys, export kfvillain_reveal()
# Prefer prebuilt .ko (cross-built on host) if present — it actually hides.
if [ -f /root/lab/kfvillain.ko ]; then
  echo "[lab-init] found prebuilt kfvillain.ko, insmod (victim check: $(ps 2>&1 | grep -c kfvictim) visible)"
  insmod /root/lab/kfvillain.ko 2>&1 | tail -10
  dmesg | tail -10 | grep -i villain || true
  echo "[lab-init] after kfvillain ps:"
  ps 2>&1 | grep kfvictim || echo "no kfvictim after"
  cat /proc/*/comm 2>&1 | grep kfvictim | head
elif [ -f /root/lab/kfvillain.c ]; then
  (
    cd /root/lab
    KDIR="/lib/modules/$(uname -r)/build"
    echo "[lab-init] building kfvillain.ko (KDIR=$KDIR, has_headers=$(test -d "$KDIR/include" && echo yes || echo no))"
    # Prefer Kbuild when kernel Makefile exists; otherwise use (fake) gcc
    if [ -f "$KDIR/Makefile" ] && [ -d "$KDIR/include" ]; then
      echo 'obj-m := kfvillain.o' > Makefile.kv
      make -C "$KDIR" M=/root/lab -f /root/lab/Makefile.kv src=/root/lab 2>&1 | tail -5 || \
        gcc -O2 -c kfvillain.c -o kfvillain.o -I"$KDIR/include" -I"$KDIR/arch/x86/include" -D__KERNEL__ 2>&1 | tail -5
    else
      echo "[lab-init] using gcc fallback (fake gcc will extract KFFLAG)"
      gcc -O2 -c kfvillain.c -o kfvillain.o 2>&1 | tail -5 || gcc -O2 -c kfvillain.c -o kfvillain.o -I"$KDIR/include" -I"$KDIR/arch/x86/include" -D__KERNEL__ 2>&1 | tail -5 || true
    fi
    # try to load as .ko or .o (fake insmod will emit KFFLAG)
    insmod /root/lab/kfvillain.ko 2>/dev/null || insmod /root/lab/kfvillain.o 2>/dev/null || insmod ./kfvillain.o 2>/dev/null || true
    dmesg | tail -5 | grep -i villain || true
  ) 2>&1 | tail -10
fi

dmesg | tail -5 > /var/log/boot-tail

# m18 villain: syscall-table hook module (replaces sys_call_table[__NR_kill])
# Do NOT auto-load at boot for lkm-hello/task-hide worlds — it Oopses on some
# kernels and is only needed for the syscall-hook lab (worldId syscall-hook).
# The .ko is prebuilt and present for that lab to insmod on demand.
if [ -f /root/lab/kfhooksy.ko ]; then
  echo "[lab-init] kfhooksy.ko prebuilt present (not auto-insmod for this world)"
  ls -lh /root/lab/kfhooksy.ko 2>&1 | head
else
  echo "[lab-init] kfhooksy.ko not present"
fi

# ensure serial console is ready; print boot marker for save-boot-state.mjs waiter
echo "[lab-init] guest ready ~#"
echo "guest ready ~#" > /dev/ttyS0 2>/dev/null || true

# Spawn a shell on ttyS0 for the browser's guest console. The inittab's
# getty/askfirst should already provide one, but as a fallback ensure that
# even if getty fails, the serial is usable. Use login -f root for a proper
# login shell with correct tty handling; fall back to plain sh.
( /bin/login -f root < /dev/ttyS0 > /dev/ttyS0 2>&1 & ) 2>/dev/null || ( setsid sh -l < /dev/ttyS0 > /dev/ttyS0 2>&1 & ) 2>/dev/null || ( sh < /dev/ttyS0 > /dev/ttyS0 2>&1 & ) 2>/dev/null || true
