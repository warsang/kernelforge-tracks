/** Lesson body: m22.l1 — Custom hypervisors: architecture from ring -1. */
export default `## The ring above the kernel

Everything so far ran inside Windows' trust boundary. A **hypervisor** sits
one level below it: CPU extensions (Intel VMX / AMD-V) add a root mode —
ring -1 — that owns the tables mapping every address and event the kernel
sees. The kernel becomes a guest and cannot detect its host by privilege
checks alone.

## The moving parts

- **VMX root vs non-root**: the hypervisor runs in VMX root; guests run in
  non-root. \`VMXON\`/\`VMLAUNCH\` enter the world; \`VMCALL\` is the guest's
  doorbell back to the host.
- **VMCS** (per-guest control structure): which events cause a
  **VM-exit** (CR/MSR writes, EPT violations, I/O, interrupts), where each
  guest's register state lives, and where execution resumes after the
  host handles an exit.
- **EPT** (Extended Page Tables): a *second* page table under the guest's
  own CR3 — guest VA -> guest PA (the kernel's view), then EPT ->
  machine PA (the truth). The hypervisor owns layer two.

## Why cheats and EDRs both want this

| capability | what it buys |
|---|---|
| EPT-based page hiding | show one byte stream to fetches, another to scans |
| CR0/CR4/MSR intercepts | watch or fake \`KiSystemCall\` patching, HVCI state |
| handle/process filtering | hide objects below \`NtQuerySystemInformation\` |
| clean-guest illusion | the visible kernel always matches the signed image |

Defensive products use the same primitives: hypervisor-backed integrity
roots re-walk memory from outside any guest tampering (m1.l4's roadmap
note), and VBS/HVCI on your machine is Microsoft shipping exactly this.

## Type-1, type-2, and "hyperjacker"

Type-1 bare-metal (Hyper-V, Xen) boots first and hosts OSes. Type-2 (VirtualBox,
Workstation) rides inside a host OS. Cheat frameworks are neither: they are
drivers that **convert the running Windows into a guest of itself**
(hyperjack) — \`bhyve\`-style minimal VMX loaders fit in a few KB of driver.
From there the original kernel keeps running, unaware its translations now
have a second floor.

## What this module models

The \`ept-shadow\` lab gives ntsim a small honest model of layer two:
a hidden hook whose GUEST view (every kd read) shows the detour, while the
HOST view stays pristine — plus the commands a defender uses to catch the
split. Lesson 2 covers EPT shadowing techniques and their detection arms
race in full.
`;
