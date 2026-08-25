/** Lesson body: m4.l1 — Pool internals & corruption forensics (markdown). */
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
bytes of 0xA5 written at allocation, located at \`user_va + size\` — the
output shows that exact address so a repair cannot miss.

A guard that no longer reads "A5 A5 ..." proves an out-of-bounds write
happened — even before anyone crashed:

    kd> !poolfind KfPb
      0xfffff90000001000  size=0x80  active  guard @ 0xfffff90000001080: intact
      0xfffff90000001200  size=0x80  active  guard @ 0xfffff90000001280:
          CORRUPTED at guard[0] @ 0xfffff90000001280 (got 0xde, expected 0xa5)

Repair is mechanical — rewrite the full trailer at its printed address, then
confirm:

    kd> eb 0xfffff90000001280 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5
    kd> !poolverify                    # clean

## The lab

The world ships "kfpooler.sys" managing three tag-KfPb blocks. An upstream
overflow already smashed one guard; kfpooler refuses to finish its integrity
pass until every guard reads clean.

1. "!poolfind KfPb" → locate the corrupted block; submit its user address
   (full 0x-prefixed hex). (answer 1)
2. Repair the guard with "eb" at the exact guard address shown by !poolfind,
   then "!poolverify" until clean.
3. kfpooler completes and DbgPrints its checksum secret — submit it. (answer 2)

## Custom debugger extensions in this lab

- \`!poolfind <tag>\` — **lab extension**: filters the allocation registry by
  tag and reads each block's live guard bytes.
  *Driver equivalent:* wrap your allocations so the sensor always knows what
  to protect:
  \`\`\`c
  typedef struct _GUARD_TRACK {
      PVOID   userVa;
      SIZE_T  size;
      ULONG   tag;
  } GUARD_TRACK;

  PVOID GuardedAlloc(SIZE_T bytes, ULONG tag, GUARD_TRACK *track)
  {
      PVOID p = ExAllocatePoolWithTag(NonPagedPool,
                                      bytes + GUARD_LEN, tag);
      if (!p) return NULL;
      RtlFillMemory((PUCHAR)p + bytes, GUARD_LEN, 0xA5); // trailing guard
      track->userVa = p; track->size = bytes; track->tag = tag;
      return p;                       // registry entry = future sweep input
  }
  \`\`\`
- \`!poolverify\` — **lab extension**: sweeps every registered guard and
  reports first-bad-byte per block. The driver-side sweep is byte-for-byte
  the loop your m4.l2 monitor compiles down to.

## Defensive framing

Pool corruption is how most "random" kernel crashes are born: today's
one-byte overflow is tomorrow's local privilege escalation (write-what-where
into a neighboring object's function pointer).

Defense ladder, cheapest first:

1. **Guard patterns + periodic sweeps** — your own trailing canaries checked
   on a timer catch overflow while it is still one write, not one crash. You
   build exactly this in m4.l2 (**KF-Sentinel v4**: sweep, attribute, convict).
2. **Special pool (Driver Verifier)** — verifier-owned allocations each get
   dedicated pages plus guard *pages*: touching past the end faults instantly
   instead of corrupting silently. Flip it on for any suspect third-party
   driver and watch the bugcheck move next door to the real culprit.
3. **Pool-tag quotas and tracking** — cap per-tag consumption so a leaky or
   hostile driver cannot exhaust nonpaged pool; attribution feeds enforcement.
4. **kCFG** — even when corruption lands, control-flow validation stops the
   classic "overwrite the adjacent function pointer" payoff.
5. **Hardware memory tagging** — MTE-class platforms tag every allocation;
   mismatched accesses fault in hardware, making software guards free.

The forensic reading matters as much as the repair: guard[0]-only damage is a
linear overflow; deep-guard damage is a wild pointer or UAF. Your monitors
should classify, not just detect — that distinction turns telemetry into an
investigation.
`;
