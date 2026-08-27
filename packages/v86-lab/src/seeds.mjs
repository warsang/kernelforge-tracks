/**
 * Per-lab guest seeds — single source of truth shared by the buildroot
 * overlay generator (scripts/build-buildroot.sh) and instructor notes.
 *
 * Threat model identical to the windows-kernel track: hashes live in the
 * catalog, plaintext lives here + docs/plan.md (instructor side). Nothing
 * student-facing prints these values before the lab work is done.
 */

export const GUEST_SEEDS = {
  "lkm-hello": {
    // /root/.kflag — read from kernel space in the lab
    kflagFile: "kf-lkm-hello",
  },
  "syscall-trace": {
    // printed by the registered kprobe when /root/trigger runs
    traceSecret: "kf-trace-ok",
    triggerBinary: "/root/trigger",
  },
  "task-hide": {
    // kfvillain.ko hides this many decoy tasks during init
    hiddenTasks: 3,
    revealSecret: "kf-detector-ok",
  },
  "syscall-hook": {
    hookedSyscall: 37, // __NR_kill i386
    detectorSecret: "kf-hookspotted",
    restoreSecret: "kf-syscall-clean",
  },
};
