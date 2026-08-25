#!/bin/sh
# Lab init overlay: spawn decoy victims, seed files, keep console ready.
# Runs from /etc/init.d/S99kflag inside the buildroot guest.

# decoy tasks the villain will hide (count pinned by src/seeds.mjs)
for i in 1 2 3; do
  setsid sh -c "exec -a kfvictim$i sleep infinity" &
done

# m7 seed: secret file read from kernel space
echo "kf-lkm-hello" > /root/.kflag

# m8 trigger binary: execve storm for kprobe labs
cat > /root/trigger <<'TRIG'
#!/bin/sh
exit 0
TRIG
chmod +x /root/trigger

# build + load the villain last so it hides the live decoys above
if [ -f /root/lab/kfvillain.c ]; then
  ( cd /root/lab && gcc -O2 -c kfvillain.c -o kfvillain.o \
      --include=/lib/modules/"$(uname -r)"/build/include/linux/module.h ) 2>/dev/null || true
fi

dmesg | tail -5 > /var/log/boot-tail

# m15 villain: syscall-table hook module
if [ -f /root/lab/kfhooksy.c ]; then
  ( cd /root/lab && gcc -O2 -c kfhooksy.c -o kfhooksy.o \
      && insmod kfhooksy.o ) >/dev/null 2>&1 || true
fi
