/** Lesson body: m22.l2 — EPT shadowing, EPT hooks & their detection. */
export default `## One address, two truths

EPT gives a hypervisor a superpower no ring-0 rootkit can match: the guest
page tables stay pristine while the **machine-frame mapping** differs per
access type. The classic split:

| access | EPT view | result |
|---|---|---|
| instruction fetch (execute) | real page | kernel executes genuine code |
| data read (scan) | decoy page | integrity scanner reads pristine bytes |
| data write | trap -> host | changes land wherever the hypervisor wants |

An **EPT hook** inverts it for stealth: point fetches at your detour and
reads at the original bytes — or hide a page entirely by marking its EPT
entry not-present and servicing the violation from the host. From inside
the guest there is no byte, table or hash that disagrees... if you only
look once through one path.

## Detection: make the two translations disagree out loud

Every known technique attacks one asymmetry of the split:

1. **Timing / A-D bits** — an EPT violation is a VM-exit: microseconds.
   Access a page twice (or flip its accessed/dirty bit) and compare
   latency; hidden pages cost extra exits. Our model counts every host-view
   read (\`reads=\` in \`!eptlist\`) as that observable.
2. **Dual-view hashing** — read the same physical frame through two
   translations (guest VA vs direct physical map). A fetch/read split shows
   up as different bytes for "the same" memory. This is exactly what
   \`!eptview\` does: host(EPT) view next to the guest view you already have
   with \`db\`.
3. **CPUID / leaf quirks** — VMX roots must intercept CPUID; subtle leaf
   values, timing of the exit, or missing features fingerprint the host.
4. **RDTSC drift** — exits around sensitive instructions skew cycle counts;
   statistical tests catch the jitter even when values are faked.
5. **TLB synthesis** — force a translation fault path and observe which
   physical frame services it; split mappings occasionally reuse frames in
   ways the guest TLB betrays.

No single check is conclusive — defenders stack several; attackers randomize
exit timing and keep decoy pages self-consistent. That race IS modern
kernel-defense engineering.

## The lab

\`ept-shadow\` boots kfhyp.sys: a detour on \`PsLookupProcessByProcessId\`
that exists ONLY below the kernel. Guest memory (every \`db\`/\`u\`) shows
the \`E9\`; the host/EPT view keeps pristine bytes:

\`\`\`
kd> !eptlist                       # what is shadowed, how often read
kd> db <thunk> L8                  # guest view: the detour
kd> !eptview <thunk>               # host view: the truth -> MISMATCH
kd> !eptverify                     # sweep every entry -> detection secret
\`\`\`

The control sample (kfhyp trampoline page) agrees between views — a reminder
that mismatches, not shadows themselves, are the tell.

## Flags

1. First byte the GUEST sees at the shadowed thunk's prologue — submit as
   two hex digits with 0x prefix (it is an unconditional near-jump opcode).
2. How many ranges \`!eptlist\` reports as shadowed (decimal).
3. The secret \`!eptverify\` prints when at least one range disagrees.
`;
