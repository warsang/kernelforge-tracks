/** Lesson body: m4.l1 — Pool internals & corruption (markdown). */
export default `## The kernel's malloc

Kernel memory comes from **pools**: \`NonPagedPool\` (always resident — what
your drivers live in) and \`PagedPool\`. Allocations are carved with a
four-character **pool tag** you choose, e.g. 'KfPb'; every block carries its
tag so pool tooling can attribute leaks and corruption to a driver.

Around each allocation lives bookkeeping the driver never sees: header
magic/size in front, pattern bytes filling alignment gaps. Overflow your
allocation by even one byte and you corrupt *someone else's* metadata —
usually discovered later, in a far-away component, as a bugcheck:

| code | name | usual cause |
|---|---|---|
| 0x19 | BAD_POOL_HEADER | smashed header / free-list damage |
| 0xC2 | BAD_POOL_CALLER | double free, bad tag, wrong-IRQL free |
| 0x50 | PAGE_FAULT_IN_NONPAGED_AREA | use-after-free landing here |

## Auditing pool from the debugger

    kd> !poolfind KfPb      # every tagged block + guard health
    kd> !poolverify         # sweep all guards; report corruption precisely

Each block prints its user address, size, state, and trailing **guard**: 16
bytes of 0xA5 written at allocation. A guard that no longer reads
"A5 A5 ..." proves an out-of-bounds write happened — even before anyone
crashed. "!poolfind" also shows the expected byte pattern, so repair is
mechanical:

    kd> eb <guard_addr> a5 a5 a5 ...   # rewrite the smashed guard
    kd> !poolverify                    # clean

## The lab

The world ships "kfpooler.sys" managing three tag-KfPb blocks. An upstream
overflow already smashed one guard; kfpooler refuses to finish its integrity
pass until every guard reads clean.

1. "!poolfind KfPb" → locate the corrupted block; submit its user address
   (full 0x-prefixed hex). (answer 1)
2. Repair the guard with "eb" using the expected bytes shown by !poolfind,
   then "!poolverify" until clean.
3. kfpooler completes and DbgPrints its checksum secret — submit it. (answer 2)

## Defensive framing

Pool corruption is how most "random" kernel crashes are born: today's
one-byte overflow is tomorrow's local privilege escalation (write-what-where
into a neighboring object's function pointer). Defenses to know: Driver
Verifier's special pool (every driver-owned block gets its own pages +
guards), pool-tag quotas and tracking, kCFG suppressing the control-flow
payload, and hardware memory tagging arriving with newer platforms.
`;
