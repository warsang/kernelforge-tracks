/** Lesson body: m9.l1 — Rootkits & detection (markdown). */
export default `## Hiding in plain sight, then turning on the lights

The guest ships with a villain: \`kfvillain.ko\`, a prebuilt rootkit that
unlinks three decoy tasks from the scheduler's task list — the Linux twin
of Module 1's DKOM lab. \`ps\` shows a clean system. The kernel knows
better.

## Writing the detector

Process accounting lives in two places that must agree:

- the scheduler's task list (what \`/proc\` enumerates), and
- \`nr_threads\` — a global count of live tasks.

A hidden task is removed from the list but still counted. The delta is
the tell:

    static int __init detect_init(void)
    {
        /* walk /proc-visible tasks vs nr_threads */
        pr_info("kfflag: hidden=%d\\n", nr_threads - visible);
        return 0;
    }

Your detector module must print the exact number of hidden tasks.

## The lab

Boot the \`task-hide\` world (the villain loads during init), then:

1. Observe the discrepancy yourself (\`ps\` output vs your module) and
   submit the decimal count of hidden tasks.
2. Extend the detector to name-and-shame: once the count is confirmed,
   the villain prints its surrender secret through your module's
   completion path (\`kfvillain_reveal()\` is exported for you).
   Submit it.

## Defensive framing

List-vs-counter invariants are one of the cheapest high-signal
rootkit detectors and they generalize: interrupt descriptor tables,
notifier chains, module lists — every "hide by unlink" technique leaves
a second bookkeeping structure untouched. Cross-validating independent
accounting is the defensive pattern to take home; production systems do
this from hypervisors or eBPF where the rootkit cannot reach.
`;
