/**
 * Course catalog v3 — Modules 1-4 (windows-kernel track), 5-6 (windows-userland
 * sogen track), 7-9 (linux-kernel v86 track). m10 (reversing/ghidra) joins in
 * the M3 milestone once the static-analysis engine lands.
 *
 * Flag "hashes" are sha256 over NORMALIZED answers (trim + lowercase) and are
 * precomputed constants (browser-safe; no crypto dep at runtime). The
 * plaintext answers live in instructor notes / docs/plan.md; prompts pin the
 * exact expected format so grading is unambiguous.
 *
 * Deterministic addresses verified against the 22h2 table set:
 *   - kftarget.exe _EPROCESS fixed by populateFromDump() at 0xffffa40bc9e73c00,
 *     ActiveProcessLinks +0x448 => answer 0xffffa40bc9e74048   (m1.l2.f1)
 *   - kfsample.exe Cid is 1312 in EVERY world (the dump overlay carries an
 *     authentic svchost.exe at 312 — Cids must stay unique system-wide)
 *   - irql-dpc world: DeferredRoutine at 0xfffff8055a401400    (m2.l1.f2)
 *   - irql-attackers world (m2.l3/m2.l4): kvmdrv.sys base
 *     0xfffff8055a700000 — victim KDPC 0xfffff8055a701000, heartbeat routine
 *     0xfffff8055a701400, canary page 0xfffff8055a702000   (KFWARZ_* in
 *     apps/web/src/scenarios.js)
 *   - pool-corrupt world: second KfPb block at 0xfffff90000001200 (m4.l1.f1)
 * Userland worlds (packages/sogen-runtime reference backend):
 *   - sauer-recon: sauerbraten.exe base 0x00400000, entity array at
 *     0x02100040, local player index 3 => VA 0x021000d0, health +0x24
 *   - sauer-hook: cl_sendinput at 0x004532a0, cheat stub at 0x0046f010
 */
import m1l0Body from "./lessons/m1-l0-concepts.mjs";
import m1l1Body from "./lessons/m1-l1.mjs";
import m1l2Body from "./lessons/m1-l2.mjs";
import m1l3Body from "./lessons/m1-l3.mjs";
import m1l4Body from "./lessons/m1-l4.mjs";
import m2l1Body from "./lessons/m2-l1.mjs";
import m2l2Body from "./lessons/m2-l2.mjs";
import m2l3Body from "./lessons/m2-l3.mjs";
import m2l4Body from "./lessons/m2-l4.mjs";
import m3l1Body from "./lessons/m3-l1.mjs";
import m3l2Body from "./lessons/m3-l2.mjs";
import m4l1Body from "./lessons/m4-l1.mjs";
import m4l2Body from "./lessons/m4-l2.mjs";
import m5l1Body from "./lessons/m5-l1.mjs";
import m6l1Body from "./lessons/m6-l1.mjs";
import m7l1Body from "./lessons/m7-l1.mjs";
import m8l1Body from "./lessons/m8-l1.mjs";
import m9l1Body from "./lessons/m9-l1.mjs";
import m10l1Body from "./lessons/m10-l1.mjs";
import {
  SENTINEL_V1_STARTER, SENTINEL_V2_STARTER, SENTINEL_V3_STARTER,
  SENTINEL_V4_STARTER,
  ATTACK_WPOFF_STARTER, ATTACK_LOCKDOWN_STARTER, ATTACK_TIMERDPC_STARTER,
  ATTACK_HIJACK_STARTER, SENSOR_TELEMETRY_STARTER, SENSOR_DEADLINE_STARTER,
  INJECT_STARTER, SMM_VAULT_STARTER, SMM_RELOC_STARTER,
} from "./starters.mjs";
import m11l1Body from "./lessons/m11-l1.mjs";
import m12l1Body from "./lessons/m12-l1.mjs";
import m13l1Body from "./lessons/m13-l1.mjs";
import m14l1Body from "./lessons/m14-l1.mjs";
import m15l1Body from "./lessons/m15-l1.mjs";
import m16l1Body from "./lessons/m16-l1.mjs";
import m17l1Body from "./lessons/m17-l1.mjs";
import m18l1Body from "./lessons/m18-l1.mjs";
import m19l1Body from "./lessons/m19-l1.mjs";
import m20l1Body from "./lessons/m20-l1.mjs";
import m20l2Body from "./lessons/m20-l2.mjs";
import m21l1Body from "./lessons/m21-l1.mjs";
import m22l1Body from "./lessons/m22-l1.mjs";
import m22l2Body from "./lessons/m22-l2.mjs";
import m23l1Body from "./lessons/m23-l1.mjs";

const F = {
  // m1.l0 primer lab: reading-comprehension + live cross-checks in the debugger
  m1l0f1: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a", // records count (4)
  m1l0f2: "a8bf30486af1378d6b0a7786939cf0f899da48bae84755112dc814683aeafbee", // ApcState field name
  m1l0f3: "885d784b273b576aaff1dd2b7fde02c961223c6749cbd5da5e159e64a10b761c", // kfsample's handle target
  m1l1f1: "5c5ff15e068d0e09659a861ee1c8894f5ab3fb9d239f176d715e3b2a526eb670",
  m1l1f2: "712dca40936b39ce670dc803736fe3735cf99311030a928de039a36f77926230", // kfsample Cid (1312 — 312 collides with a real dump svchost)
  // kftarget.exe _EPROCESS is fixed by populateFromDump() at 0xffffa40bc9e73dc0
  // and ActiveProcessLinks sits at +0x448 (22h2 tables) => 0xffffa40bc9e74208
  // (Cids/addresses follow Windows realism: multiples of 4, non-slab pool VAs)
  m1l2f1: "b521dce529fc0173433b3abf4ebbeb4f9f62a28c4d25d7a0207f41843ef58ff2",
  m1l3f1: "fac4db6ff2799f9496b9274d97f297372527ccfd2ac51d4ebcac83244a11a377",
  m2l1f1: "e629fa6598d732768f7c726b4b621285f9c3b85303900aa912017db7617d8bdb",
  m2l1f2: "eb6ac6d19614930b2043d812fa2f921182d705a123fa25a0960ba32885c1c5ec",
  m2l1f3: "6531630236cc0988185d752ba4774bdaef12e7cc3e9aafef44fac35512c90157",
  m3l1f1: "795c965da66b249e55cd9d0f73b177afea944ec6d076f81092f9657c540db6d3",
  m3l1f2: "5e968ce47ce4a17e3823c29332a39d049a8d0afb08d157eb6224625f92671a51",
  m3l1f3: "c55edb2e0282de46e56e00d9708090d56690bda1bf2fb2daa061067ba19f60dc",
  // m3.l1.lab2 (author-your-own-hook): thunk VAs are deterministic —
  // PsLookupProcessByProcessId is the 4th defineApi call => bases.thunk+0x30
  m3l1f4: "1517f7b43bddbd7889d718031169acafe107f73b267df8a0d0c3b9f97223a862",
  m3l1f5: "f8aa067dc961c4f182e93bda11cec69361b2b9882c88eeba3a1e3439aba80c34",
  // --- KF-Sentinel defense labs (windows-kernel track) ---
  m1l4f1: "5e968ce47ce4a17e3823c29332a39d049a8d0afb08d157eb6224625f92671a51", // carved victim pid (888 — Cids are multiples of 4)
  m1l4f2: "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683", // linked entries post-DKOM
  m1l4f3: "355cbb85edcf7eac7e437a0a597c733c2f41b78e98f5f2370e83e50a8c21e2ca", // sentinel v1 secret
  m2l2f1: "e629fa6598d732768f7c726b4b621285f9c3b85303900aa912017db7617d8bdb", // sampled IRQL
  m2l2f2: "06d1b91d683d670a69c021df6469f85c679de4752c44f5cc78a6e774dc64c2b9", // watchdog secret
  // --- m2.l3 attack workshop (irql-attackers world; KFWARZ_* anchors) ---
  m2l3f1: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // IRQL inside WPOFF window (2)
  m2l3f2: "b55aac633d4b14777545bf523d087015367c638adc53f00b814fd68bd701e36c", // restored CR0 (0x80010031)
  m2l3f3: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", // pinned secondary cores (3)
  m2l3f4: "d2f483672c0239f6d7dd3c9ecee6deacbcd59185855625902a8b1c1a3bd67440", // watchdog bugcheck while pinned (133)
  m2l3f5: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", // payload runs after !dpcpump 13 (3)
  m2l3f6: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // payload IRQL (2)
  m2l3f7: "50bdd9362f71492177d1a4cab90d161d6e8a374f953045f8d2879d1a201d2f89", // victim DPC VA (0xfffff8055a701000)
  m2l3f8: "c2ba879ab429219180fd28a7ea4f2c93ad6c7640d6528c7d042f4bc7ffedaade", // hijack payoff secret
  // --- m2.l4 defense workshop ---
  m2l4f1: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", // telemetry queue depth (1)
  m2l4f2: "06d1b91d683d670a69c021df6469f85c679de4752c44f5cc78a6e774dc64c2b9", // telemetry secret (=watchdog secret)
  m2l4f3: "1c33629a937098eaef1dc6e2ce9a6348aac6b541f4e515cc62c0d39690402acb", // deadline verdict (missed)
  m2l4f4: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // core 1 IRQL while pinned (2)
  m2l4f5: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d", // heartbeat timer period (5)
  m2l4f6: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", // queued DPCs at boot (1)
  m2l4f7: "0fd42b3f73c448b34940b339f87d07adf116b05c0227aad72e8f0ee90533e699", // HVCI bugcheck code (109)
  m2l4f8: "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9", // WP bit the attack cleared (0)
  m3l2f1: "cf7e5768f7f48553d460e0ae0e18158f0342c3f3f1e7674eac0e8fda3c82fab6", // attested export
  m3l2f2: "c7b4da3905c06e32b6aed4c17aba7c7ba3e49735081651cc8612d15a992ddec6", // attest secret
  m4l2f1: "50bac58f006cecfdbf8bc09893ee32e2bc3eaae6d5b92a6799645cc1463bf031", // convicted block VA
  m4l2f2: "3c0785e6ee570d27daef2e74ac2be40c2d656a92c4faf9d1b3073810d636ffd1", // poolmon secret
  m4l1f1: "50bac58f006cecfdbf8bc09893ee32e2bc3eaae6d5b92a6799645cc1463bf031",
  m4l1f2: "e00133bdd1fb36765d3379852981a2b2c7163f1a0cd1b826f82b516d6080d0d0",
  // --- windows-userland (sogen reference backend) ---
  m5l1f1: "c60c103663b60f83d7e703e9bc29f715f0f85fbafdfc93c7e8c47974b4234b88", // sauerbraten.exe base
  m5l1f2: "2dca4b7ecfdbb7cf5a40b14d27641e975bb66e4807419161dba0884efd23f729", // local player entity VA
  m5l1f3: "eb21d48944a211681df63be8d6a1a0a7a3724904bfcabda1a9b7e2f0985c3be3", // health field offset
  m6l1f1: "96fb5426e097d4f1ad8791e16d6f7c907d8ee9ba2a00fe0e299ec9857076188a", // detoured fn VA
  m6l1f2: "a38ab0ee07657cb1230654c7d2ea0849234d344222705e21dffc12e09bbd0aea", // E9 stub target VA
  m6l1f3: "578ca15def9a7b2dffd2609b50d154679c28c99cdd4b5d57a16e3384fa995d56", // inputtest secret
  // --- linux-kernel (v86 buildroot track) ---
  m7l1f1: "2747b7c718564ba5f066f0523b03e17f6a496b06851333d2d59ab6d863225848", // __NR_init_module (i386)
  m7l1f2: "4a7f740db3b813bac7d82a7b111cf73eadae8d988d30cb95476130f5a8c3aec5", // /root/.kflag secret
  m8l1f1: "4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8", // __NR_execve (i386)
  m8l1f2: "9c220b3766ff32192d40855481cf872f90cc0e9ecc4cf211f55b8a6efb2a84bc", // kprobe trace secret
  m9l1f1: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", // hidden task count
  m9l1f2: "4c368c365d47c10df5f46f7a56f46bbf2af86534cc884196e2878b34feddd0d2", // villain surrender secret
  // --- reversing (ghidra decompiler pane over the api-hook world) ---
  m10l1f1: "2747b7c718564ba5f066f0523b03e17f6a496b06851333d2d59ab6d863225848", // recovered function count (kfhook.sys grid)
  m10l1f2: "71489c0a57f4a2c1c4fd1dfdd85685d8f09a9ffe3f960f36a30191678e665e3d", // second boundary VA
  m10l1f3: "41571682d793c451794838c436413b18896cb0479575ca5ff59c160c38733537", // E9 detour target VA
  // m11: paging foundations (answers verified deterministic against the 22h2 paged boot)
  m11l1f1: "5ca025c5014c8952a23d1c125b2ee525862b64fdcf484c6dd28d180d73e5f173", // KUSER physical address via !vtop (0x101000)
  m11l1f2: "7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451", // process count in !process 0 0 (7)
  m11l1f3: "e5b564a7a4059dccb9c20cd678603a6f30c5f3db3af9b421e7f87eb37b030337", // KUSER exec class from !pte (nx)
  // m12: SMM vault exfil
  m12l1f1: "c712810a09830eb312aa0fe16773c426021e275ca28c79163e8c7e10dd24ace5", // exfiltrated secret string
  m12l1f2: "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9", // D_OPEN after D_LCK set (0)
  // m13: SMBASE relocation
  m13l1f1: "59559e557dba68f6c1bf096dcbd52ca7f6e5f2bd7ea2d8a058c5cf63204df292", // save-state SMBASE offset (0xfb04)
  m13l1f2: "513c129dfdc2aee92e26719e958855caca7d77c892d76fc576ba8efb946e2831", // planted-stub magic at landing2 (mf2k)
// --- blog labs v4 (windows-kernel: paging / edr-sensor / ssdt) ---
  m14l1f1: "2263d82fc17e3465ea0eb2d2fe69368d8e718bb6b3a62e6aeab2ea243c7ab751", // real DTB (decoy-shuffled world)
  m14l1f2: "fa23c52d20e9bc7c8cf9b23089ffd0c5636e37292d59b3c013af8208274d3855", // code-page PTE alias VA
  m14l1f3: "f58f880c2f1b062881e17ef1e7a2b83228911184225760d88310a8c40f4c157e", // NX-repair secret
  m15l1f1: "daf0604f99e857b8db1f3199cf87664004a3f20a4e4b81e7c75c0617281b42ed", // deny NTSTATUS name
  m15l1f2: "2ba183e0287b7805bdad4926afa8481094ad547d173e20abbc34e8fd7af9d463", // sensor callback VA
  m15l1f3: "0e90786bcce8173a98e2c7054e3ea3df0a7aa8a6a6e10cb7e16c221c36f5b3d5", // telemetry-gap secret
  m16l1f1: "fecde715c8483bcf15534e4dadf2417ac1f2d82425712c7c11768a7bb727b1fb", // hooked service name
  m16l1f2: "a0459593796d340d431d65b318986f7e05bf617252c1137c7370e834c5928590", // detour target VA
  m16l1f3: "21cd32f101408104d43ab2f7cb42103425bdda667d14008899268432a0b0c46c", // clean-table secret
  // --- m17 tbm-ac (sogen usermode AC gauntlet) / m18 linux syscall hook ---
  m17l1f1: "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d", // vector count
  m17l1f2: "01e743f69a7d2bad56da5433c04e57a515e8b4e366c1ac037dde2dda9d184057", // live stats VA
  m17l1f3: "796437c4999a9e5887294d61387e8ba13077a36eaacdddb06e73336605a789c6", // godmode secret
  m18l1f1: "7a61b53701befdae0eeeffaecc73f14e20b537bb0f8b91ad7c2936dc63562b25", // __NR_kill i386
  m18l1f2: "edf12aa731ae4c1c81e79821415e7ff7a222f026c8304dac470f2e75dcf158d2", // detector secret
  m18l1f3: "5922ec30f7a92494220babe4b74d77228b75de3dbdd28d9a76da04695456e58b", // restore secret
  // --- m20 hooks & integrity monitoring ---
  m20l1f1: "0fd42b3f73c448b34940b339f87d07adf116b05c0227aad72e8f0ee90533e699", // caught-hook bugcheck (109)
  m20l1f2: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a", // protected region count (4)
  m20l1f3: "4b86ca5be6355028fdf22002f8ad1958bfbcc37ebe6362da4b12ea67fab9622e", // stealth-window secret
  m20l2f1: "3df05ba6053db552571d26c662c79f7363a804a352f6e0187c1d9a9382cdbaae", // IAT
  m20l2f2: "005bc5c2e3eda888e9710622372ad53ddfaca6ac6d69d21e043dd1c159bfd1f7", // VEH
  // --- m21 userland injection (handle-based vs handleless) ---
  m21l1f1: "b287909b883b5658cca5b9590df5aa5c24c8c3bc3b2825da597778fb3613c8e3", // completion secret
  m21l1f2: "139bab6cd5244c9e0dcc9f6a24f022b8fead8cc04fea0824f704a42e39df9492", // PROCESS_VM_WRITE
  m21l1f3: "a8bf30486af1378d6b0a7786939cf0f899da48bae84755112dc814683aeafbee", // ApcState

  // --- m22 custom hypervisors & EPT shadowing ---
  m22l2f1: "f94f18e5f578ef61e81e2661642524466b535b2ff2542871239fca36f27a2fbb", // guest prologue byte (0xe9)
  m22l2f2: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // shadowed range count (2)
  m22l2f3: "745c77fd16f591e32a57fade15e9ac1b08beb08baf11c83d97ceeac4017e022c", // detection secret

  // --- m23 DKOM field labs ---
  m23l1f1: "88bc51edec8b66e243e4f1742810e0623192b86526f1545a93c001ddb12ed596", // lsass Protection byte (0x62)
  m23l1f2: "daf0604f99e857b8db1f3199cf87664004a3f20a4e4b81e7c75c0617281b42ed", // denied open status
  m23l1f3: "86edefad6b6e2d7df966ecd7a6b3e3770f155745ac13d99bca4dc99c794d524c", // PPL-off secret
  m23l1f4: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // Cid-0004 count after spoof
  m23l1f5: "a8bf30486af1378d6b0a7786939cf0f899da48bae84755112dc814683aeafbee", // identity cross-ref

  // --- m19 reversing the sensor (kfalcon grid + fixture pseudocode) ---
  m19l1f1: "a68b412c4282555f15546cf6e1fc42893b7e07f271557ceb021821098dd66c1b", // recovered function count
  m19l1f2: "2ba183e0287b7805bdad4926afa8481094ad547d173e20abbc34e8fd7af9d463", // callback VA
  m19l1f3: "a68b412c4282555f15546cf6e1fc42893b7e07f271557ceb021821098dd66c1b", // CreationStatus offset (decimal)
};

// Starter source for m3.l1.lab2. The student must discover the export
// address in the debugger and paste it into g_TargetFn before compiling.
const HOOK_AUTHOR_STARTER = `// m3.l1.lab2 - author your own inline hook
//
// kfhook.sys showed you WHAT a detour looks like; now write one yourself.
// The emulated nt! suppresses pid 888 lookups whenever the export prologue
// reads as detoured (first byte == E9). Your job:
//
//   1. Boot the lab world and discover the export's address:
//        kd> x nt!PsLookup*
//        kd> u nt!PsLookupProcessByProcessId     ; note the patched prologue bytes
//   2. Paste that address into g_TargetFn below.
//   3. Compile & load, then prove it from the debugger:
//        kd> !hookscan                           ; DETECTED INLINE HOOKS
//        kd> !hooktest PsLookupProcessByProcessId 888

#include <ntddk.h>

// TODO(lab): replace 0 with the address you found via x / u / sym
static PUCHAR g_TargetFn = (PUCHAR)0x0000000000000000;

static VOID KfHookUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if ((ULONG_PTR)g_TargetFn == 0) {
        DbgPrint("kfdetour: g_TargetFn not set - find the export address with x / u / sym\\n");
        return STATUS_UNSUCCESSFUL;
    }

    // landing pad for the jmp: a lone RET keeps the model kernel alive.
    // (Real detours copy the stolen instructions here instead of RET; see
    // the lesson's defense section for why that matters to EDRs.)
    PUCHAR tramp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, 16, 'TdKf');
    if (tramp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    tramp[0] = 0xC3;

    // jmp rel32: displacement is measured from the END of the instruction
    LONG rel = (LONG)(tramp - (g_TargetFn + 5));
    g_TargetFn[0] = 0xE9;
    *(PLONG)(g_TargetFn + 1) = rel;

    DbgPrint("kfdetour: prologue at %p now jumps to %p\\n", g_TargetFn, tramp);
    DbgPrint("kfdetour: secret=kf-hook-author-ok\\n");

    DriverObject->DriverUnload = KfHookUnload;
    return STATUS_SUCCESS;
}
`;

export const module1 = {
  id: "m1",
  title: "Windows Kernel Fundamentals & Kernel Manual Mapping",
  track: "windows-kernel",
  summary:
    "x64 kernel internals on a real dump-anchored emulated kernel: the four " +
    "places a process exists (list, threads, handles, telemetry), EPROCESS " +
    "walking, process hiding, then write and manually map your first drivers " +
    "in ntsim.",
  lessons: [
    {
      id: "m1.l0",
      title: "Kernel objects primer — the four places a process exists",
      body: m1l0Body,
      requires: [],
      labs: [
        {
          id: "m1.l0.lab1",
          kind: "windbg",
          title: "First contact: confirm rows #1–#3 in a pristine world",
          brief:
            "Boot the debugger and prove each cross-check exists BEFORE anything " +
            "is hidden: walk the process list, read a thread's ApcState " +
            "back-pointer, and enumerate the seeded handle references.",
          scenario: "boot-default",
          flags: [
            {
              id: "m1.l0.f1",
              sha256: F.m1l0f1,
              prompt:
                "The primer names several independent records an EDR diffs " +
                "against each other. Submit that count as a decimal digit.",
              points: 50,
            },
            {
              id: "m1.l0.f2",
              sha256: F.m1l0f2,
              prompt:
                "Boot the lab, run `!process kfsample 7`. The THREAD line ends " +
                "with an arrow annotation naming the process the thread " +
                "belongs to. Submit the structure field name before the -> " +
                "(one word, lowercase).",
              points: 100,
            },
            {
              id: "m1.l0.f3",
              sha256: F.m1l0f3,
              prompt:
                "Run `!handles kfsample` in the debugger. The seeded reference " +
                "shows kfsample.exe holds a handle against another lab " +
                "process — submit its exact image name.",
              points: 100,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l1",
      title: "The x64 kernel landscape",
      body: m1l1Body,
      requires: ["m1.l0"],
      labs: [
        {
          id: "m1.l1.lab1",
          kind: "windbg",
          title: "First contact: inspect the live process list",
          brief:
            "Boot ntsim, open the debugger and enumerate processes and loaded modules. " +
            "One module in the list is not part of Windows.",
          scenario: "boot-default",
          flags: [
            {
              id: "m1.l1.f1",
              sha256: F.m1l1f1,
              prompt:
                "Run `lm` in the debugger. One loaded module's name is not a real Windows " +
                "module. Submit that exact file name (including the .sys extension).",
              points: 100,
            },
            {
              id: "m1.l1.f2",
              sha256: F.m1l1f2,
              prompt:
                "Use !process 0 0 to list processes. What is the decimal PID (the Cid) of " +
                "the process named kfsample.exe? Submit just the number.",
              points: 100,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l2",
      title: "EPROCESS walking & process hiding",
      body: m1l2Body,
      requires: ["m1.l1"],
      labs: [
        {
          id: "m1.l2.lab1",
          kind: "compiler",
          title: "Write your first driver: DKOM process hiding",
          brief:
            "Compile a driver that walks PsActiveProcessHead via the real dump-anchored " +
            "EPROCESS list and unlinks a target PID. Load it in ntsim and verify in the debugger.",
          scenario: "dkom-hide",
          starterFiles: [
            { path: "driver/dkomsample.c", content: "" }, // filled by lab runtime
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m1.l2.f1",
              sha256: F.m1l2f1,
              prompt:
                "After loading your driver, !process 0 0 no longer shows kftarget.exe. " +
                "What _LIST_ENTRY address did your driver overwrite (from the DbgPrint " +
                "output)? Submit the full hex value with 0x prefix, e.g. 0xffff000000000000.",
              points: 250,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l3",
      title: "Kernel manual mapping",
      body: m1l3Body,
      requires: ["m1.l2"],
      labs: [
        {
          id: "m1.l3.lab1",
          kind: "ntsim",
          title: "Map a PE into kernel space yourself",
          brief:
            "The provided loader driver maps an arbitrary PE you supply — but its import " +
            "resolution is stubbed. Fix the mapping logic so the payload driver resolves its " +
            "imports against nt! and runs.",
          scenario: "manual-map",
          flags: [
            {
              id: "m1.l3.f1",
              sha256: F.m1l3f1,
              prompt:
                "When your mapped payload runs it DbgPrints a secret string (see !analyze -v). " +
                "Submit that secret string exactly.",
              points: 400,
            },
          ],
        },
      ],
    },
    {
      id: "m1.l4",
      title: "Defense: build KF-Sentinel v1 — process & module integrity",
      body: m1l4Body,
      requires: ["m1.l3"],
      labs: [
        {
          id: "m1.l4.lab1",
          kind: "compiler",
          title: "KF-Sentinel v1: catch DKOM and unbacked code from ring 0",
          brief:
            "The world after module 1's attacks: kftarget.exe is unlinked, an executable " +
            "pool page hides outside every module. Compile the Sentinel v1 starter — it " +
            "carves for hidden processes and classifies unbacked executable memory.",
          scenario: "sentinel-m1",
          compileTask: "sentinel-v1",
          starterFiles: [
            { path: "driver/kfsentinel_v1.c", content: SENTINEL_V1_STARTER },
          ],
          flags: [
            {
              id: "m1.l4.f1",
              sha256: F.m1l4f1,
              prompt:
                "Your sensor's carve sweep finds a process whose name signature survives in " +
                "memory while ActiveProcessLinks no longer references it. Submit that " +
                "hidden process's decimal PID as printed by your driver.",
              points: 150,
            },
            {
              id: "m1.l4.f2",
              sha256: F.m1l4f2,
              prompt:
                "Sentinel v1 walks the (linked) module list and counts linked entries on the " +
                "process list. Submit the number of LINKED entries it reports after the DKOM.",
              points: 100,
            },
            {
              id: "m1.l4.f3",
              sha256: F.m1l4f3,
              prompt:
                "When both sensors finish, Sentinel v1 prints its completion secret in the " +
                "DbgPrint buffer (!analyze -v). Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

export const module2 = {
  id: "m2",
  title: "IRQL & Deferred Procedures",
  track: "windows-kernel",
  summary:
    "The interrupt priority ladder that governs everything a driver may do, and the " +
    "deferred-procedure machinery that breaks when a driver abuses it.",
  lessons: [
    {
      id: "m2.l1",
      title: "IRQL & deferred procedure calls",
      body: m2l1Body,
      requires: ["m1.l4"],
      labs: [
        {
          id: "m2.l1.lab1",
          kind: "windbg",
          title: "Free the pinned processor",
          brief:
            "kfdpc.sys raised the IRQL during init and never lowered it. A DPC is stranded " +
            "in the per-CPU queue. Read the stuck level, record the DPC's routine address, " +
            "repair, drain.",
          scenario: "irql-dpc",
          flags: [
            {
              id: "m2.l1.f1",
              sha256: F.m2l1f1,
              prompt:
                "!irql shows the processor stuck at a level no thread should sit at. " +
                "Submit that IRQL as a decimal number.",
              points: 100,
            },
            {
              id: "m2.l1.f2",
              sha256: F.m2l1f2,
              prompt:
                "!dpcs shows exactly one queued-but-not-drained DPC. Submit its " +
                "DeferredRoutine address as full 16-digit hex with 0x prefix.",
              points: 150,
            },
             {
              id: "m2.l1.f3",
              sha256: F.m2l1f3,
              prompt:
                "Repair the level (!irql 2), drain the queue (!dpcdrain), and read the secret " +
                "the deferred routine DbgPrints (!analyze -v). Submit it exactly.",
              points: 150,
            },
          ],
        },
      ],
    },
    {
      id: "m2.l2",
      title: "Defense: KF-Sentinel v2 — IRQL watchdog & DPC forensics",
      body: m2l2Body,
      requires: ["m2.l1"],
      labs: [
        {
          id: "m2.l2.lab1",
          kind: "compiler",
          title: "KF-Sentinel v2: watchdog the interrupt ladder from ring 0",
          brief:
            "Same pinned-IRQL world you freed in m2.l1 — but now your own compiled driver " +
            "samples KeGetCurrentIrql, reports the stall, restores DISPATCH_LEVEL and " +
            "releases the stranded DPC.",
          scenario: "irql-dpc",
          compileTask: "sentinel-v2",
          starterFiles: [
            { path: "driver/kfsentinel_v2.c", content: SENTINEL_V2_STARTER },
          ],
          flags: [
            {
              id: "m2.l2.f1",
              sha256: F.m2l2f1,
              prompt:
                "Your compiled watchdog samples the IRQL in DriverEntry. What level does it " +
                "report? Submit as a decimal number.",
              points: 100,
            },
            {
              id: "m2.l2.f2",
              sha256: F.m2l2f2,
              prompt:
                "After the watchdog restores the ladder and you drain with !dpcdrain, the " +
                "watchdog's acknowledgement secret is in the DbgPrint buffer. Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
    {
      id: "m2.l3",
      title: "Attack workshop: four IRQL/DPC techniques",
      body: m2l3Body,
      requires: ["m2.l2"],
      labs: [
        {
          id: "m2.l3.lab1",
          kind: "compiler",
          title: "WPOFFx64 — patch read-only memory inside a raised window",
          brief:
            "Compile the classic cheat-loader primitive: KeRaiseIrqlToDpcLevel, clear CR0.WP, " +
            "copy a detour over kvmdrv.sys's protected canary, restore. Prove it with !pgscan.",
          scenario: "irql-attackers",
          compileTask: "attack-wpoff",
          starterFiles: [
            { path: "driver/kfwpoff.c", content: ATTACK_WPOFF_STARTER },
          ],
          flags: [
            {
              id: "m2.l3.f1",
              sha256: F.m2l3f1,
              prompt:
                "Inside the tamper window the driver DbgPrints the IRQL it is executing at. " +
                "Submit that level as a decimal number.",
              points: 100,
            },
            {
              id: "m2.l3.f2",
              sha256: F.m2l3f2,
              prompt:
                "After WPON runs, !pgscan shows the CR0 value the attack restored. Submit it " +
                "as full hex with 0x prefix.",
              points: 150,
            },
          ],
        },
        {
          id: "m2.l3.lab2",
          kind: "compiler",
          title: "Directed-DPC CPU lockdown",
          brief:
            "Park every other core at DISPATCH_LEVEL with spinning directed DPCs (the OffSec " +
            "rootkit pattern), inspect with !irql -a, then keep the pins and meet 0x133.",
          scenario: "irql-attackers",
          compileTask: "attack-lockdown",
          starterFiles: [
            { path: "driver/kflockdown.c", content: ATTACK_LOCKDOWN_STARTER },
          ],
          flags: [
            {
              id: "m2.l3.f3",
              sha256: F.m2l3f3,
              prompt:
                "With your lockdown loaded (release line commented out), '!irql -a' shows the " +
                "secondary cores parked at DISPATCH. How many cores are pinned? Decimal.",
              points: 100,
            },
            {
              id: "m2.l3.f4",
              sha256: F.m2l3f4,
              prompt:
                "While the cores are pinned, run !dpcwatchdog. Which bugcheck code fires? " +
                "Submit as decimal (no 0x).",
              points: 150,
            },
          ],
        },
        {
          id: "m2.l3.lab3",
          kind: "compiler",
          title: "Timer-DPC persistence",
          brief:
            "Arm a periodic KTIMER whose DPC runs payload code — due in 3 ticks, period 5. " +
            "Make time pass with !dpcpump and count the executions in !dpcstat.",
          scenario: "irql-attackers",
          compileTask: "attack-timerdpc",
          starterFiles: [
            { path: "driver/kftimerdpc.c", content: ATTACK_TIMERDPC_STARTER },
          ],
          flags: [
            {
              id: "m2.l3.f5",
              sha256: F.m2l3f5,
              prompt:
                "After loading your driver and running '!dpcpump 13', how many times did the " +
                "payload routine run? Decimal.",
              points: 100,
            },
            {
              id: "m2.l3.f6",
              sha256: F.m2l3f6,
              prompt:
                "The payload DbgPrints the IRQL it executes at on every run. Submit that " +
                "level as a decimal number.",
              points: 100,
            },
          ],
        },
        {
          id: "m2.l3.lab4",
          kind: "compiler",
          title: "KDPC.DeferredRoutine hijack",
          brief:
            "kvmdrv.sys already queued its heartbeat DPC. Rewrite DeferredRoutine in place, " +
            "drain, and watch the retire path execute YOUR function inside the victim slot.",
          scenario: "irql-attackers",
          compileTask: "attack-hijack",
          starterFiles: [
            { path: "driver/kfhijack.c", content: ATTACK_HIJACK_STARTER },
          ],
          flags: [
            {
              id: "m2.l3.f7",
              sha256: F.m2l3f7,
              prompt:
                "!dpcs shows kvmdrv's queued victim DPC. Submit its struct address as full " +
                "16-digit hex with 0x prefix.",
              points: 100,
            },
            {
              id: "m2.l3.f8",
              sha256: F.m2l3f8,
              prompt:
                "After the hijacked drain, kvmdrv's payoff hook prints a secret confirming " +
                "the redirection (!analyze -v). Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
    {
      id: "m2.l4",
      title: "Defense workshop: watchdogs, telemetry & ceilings",
      body: m2l4Body,
      requires: ["m2.l3"],
      labs: [
        {
          id: "m2.l4.lab1",
          kind: "compiler",
          title: "Telemetry sensor on the pinned world",
          brief:
            "Defense #1: sample IRQL plus pending-DPC depth on m2.l1's crime scene, restore " +
            "the ladder and drain. Behavior over time beats structure snapshots.",
          scenario: "irql-dpc",
          compileTask: "sentinel-telemetry",
          starterFiles: [
            { path: "driver/kfsentinel_telemetry.c", content: SENSOR_TELEMETRY_STARTER },
          ],
          flags: [
            {
              id: "m2.l4.f1",
              sha256: F.m2l4f1,
              prompt:
                "Your telemetry sensor reports the pending-DPC queue depth on boot. Decimal.",
              points: 100,
            },
            {
              id: "m2.l4.f2",
              sha256: F.m2l4f2,
              prompt:
                "After the sensor restores the ladder and you drain with !dpcdrain, the " +
                "acknowledgement secret appears in the DbgPrint buffer. Submit it exactly.",
              points: 150,
            },
          ],
        },
        {
          id: "m2.l4.lab2",
          kind: "compiler",
          title: "Self-watchdog deadline alarm",
          brief:
            "Defense #2: arm a periodic watchdog DPC on core 1, then perform the Attack-2 " +
            "lockdown against yourself. The missed deadline you observe is exactly what " +
            "BattlEye/EAC-class products alarm on.",
          scenario: "irql-attackers",
          compileTask: "sensor-deadline",
          starterFiles: [
            { path: "driver/kfdeadline.c", content: SENSOR_DEADLINE_STARTER },
          ],
          flags: [
            {
              id: "m2.l4.f3",
              sha256: F.m2l4f3,
              prompt:
                "With core 1 pinned, the watchdog DPC cannot retire. What one-word verdict " +
                "does the sensor print?",
              points: 100,
            },
            {
              id: "m2.l4.f4",
              sha256: F.m2l4f4,
              prompt:
                "The sensor DbgPrints core 1's IRQL right after pinning. Submit it as a " +
                "decimal number.",
              points: 100,
            },
          ],
        },
        {
          id: "m2.l4.lab3",
          kind: "windbg",
          title: "Baseline forensics sweep",
          brief:
            "Memorize the clean world: !dpcstat shows the heartbeat timer's cadence, !irql -a " +
            "shows every core idle, !pgscan reports zero anomalies. Every attack in m2.l3 " +
            "breaks exactly one line of this baseline.",
          scenario: "irql-attackers",
          flags: [
            {
              id: "m2.l4.f5",
              sha256: F.m2l4f5,
              prompt:
                "!dpcstat shows kvmdrv's armed heartbeat timer. What is its re-arm period in " +
                "ticks? Decimal.",
              points: 100,
            },
            {
              id: "m2.l4.f6",
              sha256: F.m2l4f6,
              prompt:
                "!dpcs / !dpcstat at boot: how many DPCs are queued in the healthy world? " +
                "Decimal.",
              points: 100,
            },
          ],
        },
        {
          id: "m2.l4.lab4",
          kind: "compiler",
          title: "The HVCI ceiling — WPOFFx64 meets VBS",
          brief:
            "Same WPOFFx64 source, hardened world: the WP-clearing mov cr0 is intercepted " +
            "with CRITICAL_STRUCTURE_CORRUPTION. Confirm via !analyze -v and !pgscan.",
          scenario: "irql-hardened",
          compileTask: "attack-wpoff-hvci",
          starterFiles: [
            { path: "driver/kfwpoff_hardened.c", content: ATTACK_WPOFF_STARTER },
          ],
          flags: [
            {
              id: "m2.l4.f7",
              sha256: F.m2l4f7,
              prompt:
                "On the hardened world the WP-clear never lands. Which bugcheck code does the " +
                "model raise? Decimal (no 0x).",
              points: 150,
            },
            {
              id: "m2.l4.f8",
              sha256: F.m2l4f8,
              prompt:
                "The interception fired because the write cleared one specific control bit to " +
                "a new value. Which value did the attack set that bit to? Decimal.",
              points: 100,
            },
          ],
        },
      ],
    },
  ],
};

export const module3 = {
  id: "m3",
  title: "Inline Hooks & Control Flow",
  track: "windows-kernel",
  summary:
    "Function prologues rewritten under the kernel's feet: find the detour, understand " +
    "what it suppresses, restore honest control flow.",
  lessons: [
    {
      id: "m3.l1",
      title: "Inline hooks & control flow",
      body: m3l1Body,
      requires: ["m2.l4"],
      labs: [
        {
          id: "m3.l1.lab1",
          kind: "windbg",
          title: "Unhook PsLookupProcessByProcessId",
          brief:
            "kfhook.sys detoured one executive export to make one process invisible to " +
            "lookup. Scan for the detour, identify the hidden PID, repair the prologue, prove it.",
          scenario: "api-hook",
          flags: [
            {
              id: "m3.l1.f1",
              sha256: F.m3l1f1,
              prompt:
                "!hookscan finds exactly one detoured nt! export. Which routine is it? " +
                "Submit the exact export name.",
              points: 150,
            },
            {
              id: "m3.l1.f2",
              sha256: F.m3l1f2,
              prompt:
                "The hook suppresses lookups for exactly one PID (probe with !hooktest). " +
                "Submit that decimal PID.",
              points: 100,
            },
            {
              id: "m3.l1.f3",
              sha256: F.m3l1f3,
              prompt:
                "Restore the original prologue bytes shown by !hookscan (use eb), then run " +
                "!hooktest on the same lookup. Which symbolic NTSTATUS comes back now? " +
                "Submit its name, e.g. STATUS_ACCESS_DENIED style.",
              points: 150,
            },
          ],
        },
        {
          id: "m3.l1.lab2",
          kind: "compiler",
          title: "Author the detour yourself",
          brief:
            "Flip sides: find PsLookupProcessByProcessId's address in the debugger " +
            "(x / u / sym), paste it into the driver template, compile and load it — " +
            "your code writes the E9 detour that makes pid 888 unlookupable. Prove with " +
            "!hookscan and !hooktest.",
          scenario: "api-hook-blank",
          compileTask: "inline-hook",
          starterFiles: [
            { path: "driver/kfhookauthor.c", content: HOOK_AUTHOR_STARTER },
          ],
          flags: [
            {
              id: "m3.l1.f4",
              sha256: F.m3l1f4,
              prompt:
                "Before compiling: find the address of nt!PsLookupProcessByProcessId yourself " +
                "(`x nt!PsLookup*`, then `u` or `sym <addr>`). Submit the full hex address " +
                "with 0x prefix as shown by x.",
              points: 150,
            },
            {
              id: "m3.l1.f5",
              sha256: F.m3l1f5,
              prompt:
                "After your driver loads and !hookscan reports the detour, !hooktest " +
                "PsLookupProcessByProcessId 888 proves suppression — and the DbgPrint buffer " +
                "holds your driver's secret line. Submit the secret value exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
    {
      id: "m3.l2",
      title: "Defense: KF-Sentinel v3 — prologue attestation engine",
      body: m3l2Body,
      requires: ["m3.l1"],
      labs: [
        {
          id: "m3.l2.lab1",
          kind: "compiler",
          title: "KF-Sentinel v3: attest export prologues from inside the kernel",
          brief:
            "The api-hook world, defended this time. Compile an attestation sensor that " +
            "resolves critical exports, compares their first bytes against a known-good " +
            "baseline, and convicts kfhook.sys's detour from ring 0.",
          scenario: "api-hook",
          compileTask: "sentinel-v3",
          starterFiles: [
            { path: "driver/kfsentinel_v3.c", content: SENTINEL_V3_STARTER },
          ],
          flags: [
            {
              id: "m3.l2.f1",
              sha256: F.m3l2f1,
              prompt:
                "Your attestation sensor reports exactly one export whose live first byte " +
                "diverges from the baseline. Submit that export's name.",
              points: 150,
            },
            {
              id: "m3.l2.f2",
              sha256: F.m3l2f2,
              prompt:
                "On conviction the sensor prints its completion secret to the DbgPrint buffer. " +
                "Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

export const module4 = {
  id: "m4",
  title: "Pool Internals & Corruption",
  track: "windows-kernel",
  summary:
    "Pool tags, guard patterns and the forensic trail an out-of-bounds write leaves " +
    "before anything crashes.",
  lessons: [
    {
      id: "m4.l1",
      title: "Pool internals & corruption forensics",
      body: m4l1Body,
      requires: ["m3.l2"],
      labs: [
        {
          id: "m4.l1.lab1",
          kind: "windbg",
          title: "Catch the overflow before it crashes",
          brief:
            "kfpooler.sys manages tagged KfPb blocks; an upstream overflow already smashed " +
            "one trailing guard. Find the block, repair the guard, let the integrity pass finish.",
          scenario: "pool-corrupt",
          flags: [
            {
              id: "m4.l1.f1",
              sha256: F.m4l1f1,
              prompt:
                "!poolfind KfPb lists three allocations; exactly one has a corrupted guard. " +
                "Submit that block's user address as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m4.l1.f2",
              sha256: F.m4l1f2,
              prompt:
                "Rewrite the smashed guard bytes shown by !poolfind (eb), confirm with " +
                "!poolverify, and read the checksum secret kfpooler DbgPrints. Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
    {
      id: "m4.l2",
      title: "Defense: KF-Sentinel v4 — pool integrity monitor",
      body: m4l2Body,
      requires: ["m4.l1"],
      labs: [
        {
          id: "m4.l2.lab1",
          kind: "compiler",
          title: "KF-Sentinel v4: sweep pool guards from your own driver",
          brief:
            "The pool-corrupt world, defended. Compile a monitor that sweeps the trailing " +
            "A5 guards of every tracked KfPb block, attributes corruption to its fence, and " +
            "reports the overflow before anything crashes.",
          scenario: "pool-corrupt",
          compileTask: "sentinel-v4",
          starterFiles: [
            { path: "driver/kfsentinel_v4.c", content: SENTINEL_V4_STARTER },
          ],
          flags: [
            {
              id: "m4.l2.f1",
              sha256: F.m4l2f1,
              prompt:
                "Your monitor convicts exactly one block. Submit its user address as full " +
                "16-digit hex with 0x prefix (as printed by your driver).",
              points: 150,
            },
            {
              id: "m4.l2.f2",
              sha256: F.m4l2f2,
              prompt:
                "On conviction the monitor prints its completion secret to the DbgPrint " +
                "buffer (!analyze -v). Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module5 = {
  id: "m5",
  title: "Userland Recon Under an Emulator",
  track: "windows-userland",
  summary:
    "Process-space game hacking inside a sogen-style userspace emulator: module " +
    "enumeration, memory scans, entity hunting in a headless Sauerbraten target.",
  lessons: [
    {
      id: "m5.l1",
      title: "Modules, scans & the local player",
      body: m5l1Body,
      requires: ["m4.l2"],
      labs: [
        {
          id: "m5.l1.lab1",
          kind: "sogen",
          title: "Find the local player entity",
          brief:
            "Boot the emulated Sauerbraten process, enumerate its modules, then use the " +
            "two-scan technique (with !damage as your oracle) to locate your own entity.",
          scenario: "sauer-recon",
          flags: [
            {
              id: "m5.l1.f1",
              sha256: F.m5l1f1,
              prompt:
                "Run lm in the userland console. Submit sauerbraten.exe's image base as " +
                "full 8-digit hex with 0x prefix (e.g. 0x00400000).",
              points: 100,
            },
            {
              id: "m5.l1.f2",
              sha256: F.m5l1f2,
              prompt:
                "Scan for live health values, filter with !damage + re-scan, and find the " +
                "entity whose name is kfgamer. Submit that entity's address as full " +
                "8-digit hex with 0x prefix.",
              points: 250,
            },
            {
              id: "m5.l1.f3",
              sha256: F.m5l1f3,
              prompt:
                "Using x on your entity before/after !damage, work out the health field's " +
                "offset within the entity struct. Submit it as short 0x-prefixed hex " +
                "(e.g. 0x10).",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module6 = {
  id: "m6",
  title: "Userland Hooks & Input Flow",
  track: "windows-userland",
  summary:
    "The Module-3 detour craft applied in process space: find a cheat's inline " +
    "patch over the engine input path, resolve its trampoline, restore honest flow.",
  lessons: [
    {
      id: "m6.l1",
      title: "Detours over cl_sendinput",
      body: m6l1Body,
      requires: ["m5.l1"],
      labs: [
        {
          id: "m6.l1.lab1",
          kind: "sogen",
          title: "Unhook the input path",
          brief:
            "A cheat stub rewrote the prologue of cl_sendinput to aim-assist every packet. " +
            "hookscan it, resolve the E9 target, repair with eb, prove it with !inputtest.",
          scenario: "sauer-hook",
          flags: [
            {
              id: "m6.l1.f1",
              sha256: F.m6l1f1,
              prompt:
                "hookscan finds exactly one detoured function. Submit its VA as full " +
                "8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m6.l1.f2",
              sha256: F.m6l1f2,
              prompt:
                "Resolve the detour: target = site + 5 + rel32 (hookscan prints both). " +
                "Submit the cheat stub's VA as full 8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m6.l1.f3",
              sha256: F.m6l1f3,
              prompt:
                "Restore the original prologue bytes shown by hookscan (eb), confirm " +
                "hookscan is clean, then run !inputtest and submit the secret string " +
                "the honest path prints.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

export const module7 = {
  id: "m7",
  title: "Linux LKM Fundamentals",
  track: "linux-kernel",
  summary:
    "A real i386 Linux kernel booted by v86 inside the browser tab: write, ship " +
    "and load your first loadable kernel modules against a frozen syscall ABI.",
  lessons: [
    {
      id: "m7.l1",
      title: "Hello, kernel module",
      body: m7l1Body,
      requires: ["m6.l1"],
      labs: [
        {
          id: "m7.l1.lab1",
          kind: "linux",
          title: "insmod your first .ko",
          brief:
            "Compile a greeting module in the IDE tab, push it into the buildroot guest, " +
            "insmod it, and read dmesg over serial.",
          scenario: "lkm-hello",
          flags: [
            {
              id: "m7.l1.f1",
              sha256: F.m7l1f1,
              prompt:
                "Linux syscall numbers are a frozen per-arch ABI. Submit init_module's " +
                "decimal syscall number on i386.",
              points: 100,
            },
            {
              id: "m7.l1.f2",
              sha256: F.m7l1f2,
              prompt:
                "Extend your module to read /root/.kflag from kernel space and print it " +
                "with pr_info. Submit the file's secret string exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module8 = {
  id: "m8",
  title: "Syscall Internals & Tracing",
  track: "linux-kernel",
  summary:
    "The int-0x80 choke point, sys_call_table mechanics, and non-invasive " +
    "observation with kprobes — instrumentation without patching.",
  lessons: [
    {
      id: "m8.l1",
      title: "Watch the boundary with kprobes",
      body: m8l1Body,
      requires: ["m7.l1"],
      labs: [
        {
          id: "m8.l1.lab1",
          kind: "linux",
          title: "Probe execve",
          brief:
            "Register a kprobe on the program-execution syscall, trigger it with " +
            "/root/trigger in the guest, and capture your handler's output.",
          scenario: "syscall-trace",
          flags: [
            {
              id: "m8.l1.f1",
              sha256: F.m8l1f1,
              prompt:
                "Your probe must fire when programs start. Submit execve's decimal " +
                "syscall number on i386.",
              points: 100,
            },
            {
              id: "m8.l1.f2",
              sha256: F.m8l1f2,
              prompt:
                "With your kprobe registered and /root/trigger executed, submit the " +
                "secret string your handler prints.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module9 = {
  id: "m9",
  title: "Rootkits & Detection",
  track: "linux-kernel",
  summary:
    "A prebuilt villain rootkit unlinks tasks behind your back; write the " +
    "cross-accounting detector that catches it.",
  lessons: [
    {
      id: "m9.l1",
      title: "Catch the task-unlinking rootkit",
      body: m9l1Body,
      requires: ["m8.l1"],
      labs: [
        {
          id: "m9.l1.lab1",
          kind: "linux",
          title: "Detect what ps cannot see",
          brief:
            "kfvillain.ko hides decoy tasks during boot. Measure the scheduler-list vs " +
            "nr_threads discrepancy, then make the villain confess.",
          scenario: "task-hide",
          flags: [
            {
              id: "m9.l1.f1",
              sha256: F.m9l1f1,
              prompt:
                "Compare nr_threads against /proc-visible tasks with your detector " +
                "module. How many tasks are hidden? Submit the decimal count.",
              points: 200,
            },
            {
              id: "m9.l1.f2",
              sha256: F.m9l1f2,
              prompt:
                "Call the exported kfvillain_reveal() once your count is confirmed; " +
                "the villain prints its surrender secret through your completion path. " +
                "Submit it exactly.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};



export const module10 = {
  id: "m10",
  title: "Static Analysis with Ghidra-Grade Tooling",
  track: "reversing",
  summary:
    "Function-boundary recovery and decompilation in the browser: Ghidra's " +
    "native decompiler engine as an analysis pane over live emulated worlds.",
  lessons: [
    {
      id: "m10.l1",
      title: "From bytes to functions to pseudocode",
      body: m10l1Body,
      requires: ["m9.l1"],
      labs: [
        {
          id: "m10.l1.lab1",
          kind: "windbg",
          title: "Recover control flow statically",
          brief:
            "Boot the api-hook world and analyze it without executing anything: " +
            "!funcs recovers kfhook.sys's functions; !hookscan resolves the detour.",
          scenario: "api-hook",
          flags: [
            {
              id: "m10.l1.f1",
              sha256: F.m10l1f1,
              prompt:
                "Run !funcs kfhook.sys. How many functions does the boundary scan " +
                "recover? Submit the decimal count.",
              points: 150,
            },
            {
              id: "m10.l1.f2",
              sha256: F.m10l1f2,
              prompt:
                "Submit the VA where !funcs places the SECOND recovered function, " +
                "as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m10.l1.f3",
              sha256: F.m10l1f3,
              prompt:
                "!hookscan resolves the detoured export's E9 target inside kfhook.sys. " +
                "Submit that target VA as full 16-digit hex with 0x prefix.",
              points: 200,
            },
          ],
        },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------
// m11-m13: SMM / SMRAM track (guest paging + chipset emulation)
// ---------------------------------------------------------------------------

export const module11 = {
  id: "m11",
  title: "x64 Paging & the SMM Landscape",
  track: "smm",
  summary:
    "Boot the platform's first guest-paged kernel: walk real 4-level page " +
    "tables with !vtop/!pte/!cr, meet KUSER_SHARED_DATA's dual mapping, and " +
    "decode a Q35-style chipset whose SMRAM door was never locked.",
  lessons: [
    {
      id: "m11.l1",
      title: "Page tables you can touch, an SMI you can't mask",
      body: m11l1Body,
      requires: ["m10.l1"],
      labs: [
        {
          id: "m11.l1.lab1",
          kind: "windbg",
          title: "Walk the MMU",
          brief:
            "Boot the smm-foundations world. Use !vtop, !pte and !cr to answer " +
            "three questions about how this kernel really maps memory.",
          scenario: "smm-foundations",
          flags: [
            {
              id: "m11.l1.f1",
              sha256: F.m11l1f1,
              prompt:
                "!vtop 0xfffff78000000000 maps the kernel alias of KUSER_SHARED_DATA. " +
                "Submit the physical address it reports (0x-prefixed hex).",
              points: 150,
            },
            {
              id: "m11.l1.f2",
              sha256: F.m11l1f2,
              prompt:
                "How many processes does !process 0 0 show in this world? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m11.l1.f3",
              sha256: F.m11l1f3,
              prompt:
                "!pte 0x7ffe0000 ends with the page's exec class. Is KUSER_SHARED_DATA " +
                "mapped X or NX here? Submit nx or x (lowercase).",
              points: 100,
            },
          ],
        },
      ],
    },
  ],
};

export const module12 = {
  id: "m12",
  title: "Ring-0 → SMM Escalation",
  track: "smm",
  summary:
    "Write the exploit yourself: open the unlocked SMRAM vault from ring 0, " +
    "patch the SMI handler with your own bytes, close the door behind you, " +
    "and make ring -2 exfiltrate its secrets through port 0xB2.",
  lessons: [
    {
      id: "m12.l1",
      title: "Open the vault, patch the handler, steal the secret",
      body: m12l1Body,
      requires: ["m11.l1"],
      labs: [
        {
          id: "m12.l1.lab1",
          kind: "compiler",
          title: "SMI-handler hijack for fun and exfiltration",
          brief:
            "Compile your ring-0 exploit in the IDE, load it into the smm-vault " +
            "world, and let the modeled SMI run YOUR handler below ring 0.",
          scenario: "smm-vault",
          compileTask: "smm-vault",
          starterFiles: [
            { path: "driver/smm_vault.c", content: SMM_VAULT_STARTER },
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m12.l1.f1",
              sha256: F.m12l1f1,
              prompt:
                "After the SMI fires, the landing page dump shows an ASCII secret. " +
                "Submit it (lowercase, hyphens included).",
              points: 300,
            },
            {
              id: "m12.l1.f2",
              sha256: F.m12l1f2,
              prompt:
                "Finish by setting D_LCK from your driver, then run !smmc: what is " +
                "D_OPEN now? Submit 0 or 1.",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const module13 = {
  id: "m13",
  title: "SMBASE Relocation Persistence",
  track: "smm",
  summary:
    "The capstone: rewrite the save-state's SMBASE field before RSM so the " +
    "next SMI enters code YOU planted — persistence below ring 0, then lock " +
    "the door and prove your own exploit dead.",
  lessons: [
    {
      id: "m13.l1",
      title: "Relocate SMBASE, plant your stub, survive reboot-less forever",
      body: m13l1Body,
      requires: ["m12.l1"],
      labs: [
        {
          id: "m13.l1.lab1",
          kind: "compiler",
          title: "Two SMIs, one relocated CPU",
          brief:
            "Extend your vault exploit: relocate SMBASE via the save state and " +
            "plant a stub at the new base. The lab fires two SMIs; the second one " +
            "is yours.",
          scenario: "smm-reloc",
          compileTask: "smm-reloc",
          starterFiles: [
            { path: "driver/smm_reloc.c", content: SMM_RELOC_STARTER },
            { path: "driver/ntddk_subset.h", content: "" },
            { path: "Makefile", content: "" },
          ],
          flags: [
            {
              id: "m13.l1.f1",
              sha256: F.m13l1f1,
              prompt:
                "Which save-state offset (SMBASE-relative) holds SMBASE itself? " +
                "Submit as 0x-prefixed lowercase hex — this is the canonical anchor " +
                "from SDM Vol.3 ch.34.",
              points: 200,
            },
            {
              id: "m13.l1.f2",
              sha256: F.m13l1f2,
              prompt:
                "If relocation worked, landing #2 shows a 4-byte magic your stub wrote. " +
                "Submit that magic (lowercase).",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};


// ---------------------------------------------------------------------------
// m14-m19: blog-labs v4 additions (paging-walk / edr-sensor / ssdt-hook /
// tbm-ac / linux syscall-hook / sensor reversing) — merged from
// feat/internals-blog-modules, renumbered +3 to follow the smm track.
// ---------------------------------------------------------------------------
export const module14 = {
  id: "m14",
  title: "x64 Virtual Memory & Page Tables",
  track: "windows-kernel",
  summary:
    "Four-level translation on real PML4/PDPT/PD/PT bytes: CR3 walking, " +
    "self-map alias math, hardware PTE bits — and an EAC-style CR3 shuffle.",
  lessons: [
    {
      id: "m14.l1",
      title: "Walk the tables, heal the bit",
      body: m14l1Body,
      requires: ["m13.l1"],
      labs: [
        {
          id: "m14.l1.lab1",
          kind: "windbg",
          title: "From CR3 to a healed NX",
          brief:
            "Boot paging-walk. Identify the real DirectoryTableBase under a " +
            "shuffled decoy, compute the code page's PTE alias by hand, clear " +
            "the smashed NX bit and release the integrity secret.",
          scenario: "paging-walk",
          flags: [
            {
              id: "m14.l1.f1",
              sha256: F.m14l1f1,
              prompt:
                "!cr3 kftarget shows its DTB. The lowest frames are a decoy; " +
                "submit kftarget's REAL DirectoryTableBase as full 16-digit " +
                "hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m14.l1.f2",
              sha256: F.m14l1f2,
              prompt:
                "Split the code VA (!pte prints it) into 9-bit fields and " +
                "compute its PTE self-map alias va(s,pml4,pdpt,pd,pt*8). " +
                "Submit that VA as full 16-digit hex with 0x prefix.",
              points: 200,
            },
            {
              id: "m14.l1.f3",
              sha256: F.m14l1f3,
              prompt:
                "Clear NX (bit 63) on the code-page PTE via eb through the " +
                "alias, then !vtop the code VA. Submit the secret the " +
                "integrity pass prints.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module15 = {
  id: "m15",
  title: "Kernel Callbacks & EDR Sensors",
  track: "windows-kernel",
  summary:
    "Falcon-style process-creation telemetry with real callback machine " +
    "code: enumerate the sensor, read its CreationStatus kill switch, blind it.",
  lessons: [
    {
      id: "m15.l1",
      title: "Inside the mini-Falcon",
      body: m15l1Body,
      requires: ["m14.l1"],
      labs: [
        {
          id: "m15.l1.lab1",
          kind: "windbg",
          title: "Blind the process-create sensor",
          brief:
            "kfalcon.sys blocks kfimplant.exe spawns. Enumerate callbacks, " +
            "trigger the block, locate the name-compare immediates in the " +
            "callback body, patch one byte so the implant slips through.",
          scenario: "edr-sensor",
          flags: [
            {
              id: "m15.l1.f1",
              sha256: F.m15l1f1,
              prompt:
                "!notifytest kfimplant.exe gets blocked. Which symbolic " +
                "NTSTATUS lands in CreationStatus? Submit its name, e.g. " +
                "STATUS_ACCESS_DENIED style.",
              points: 100,
            },
            {
              id: "m15.l1.f2",
              sha256: F.m15l1f2,
              prompt:
                "!notifyroutines lists the registered Ex callback. Submit " +
                "its VA as full 16-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m15.l1.f3",
              sha256: F.m15l1f3,
              prompt:
                "Patch one immediate of the name compare (eb) so the " +
                "callback can never match, rerun !notifytest, and submit " +
                "the telemetry-gap secret from !analyze -v.",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};

export const module16 = {
  id: "m16",
  title: "SSDT & Syscall Hooking",
  track: "windows-kernel",
  summary:
    "A modeled KiServiceTable over real thunks: scan for the inline-detoured " +
    "service, resolve its rel32 target, repair, and re-scan until clean.",
  lessons: [
    {
      id: "m16.l1",
      title: "Clean the service table",
      body: m16l1Body,
      requires: ["m15.l1"],
      labs: [
        {
          id: "m16.l1.lab1",
          kind: "windbg",
          title: "Find and repair the detoured service",
          brief:
            "kfvillain.sys detoured one KiServiceTable entry to hide pid " +
            "888. Scan the table, resolve the E9 target, restore the " +
            "prologue, prove the lookup succeeds.",
          scenario: "ssdt-hook",
          flags: [
            {
              id: "m16.l1.f1",
              sha256: F.m16l1f1,
              prompt:
                "!ssdt marks exactly one HOOKED service. Submit its export " +
                "name exactly (e.g. NtOpenProcess style).",
              points: 100,
            },
            {
              id: "m16.l1.f2",
              sha256: F.m16l1f2,
              prompt:
                "Resolve the detour: target = site + 5 + rel32 (!ssdt " +
                "prints it). Submit the kfvillain.sys VA as full 16-digit " +
                "hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m16.l1.f3",
              sha256: F.m16l1f3,
              prompt:
                "Restore the pristine prologue with eb, re-run !ssdt until " +
                "it reports clean, and submit the secret kfvillain prints " +
                "(see !analyze -v).",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module17 = {
  id: "m17",
  title: "Userland Anti-Cheat Bypass Gauntlet",
  track: "windows-userland",
  summary:
    "A TryBypassMe-style ring-3 gauntlet: blacklists, PEB debugger artifacts, " +
    "XOR-encrypted stats with shadow canaries — reach godmode without a tick.",
  lessons: [
    {
      id: "m17.l1",
      title: "Quiet the five vectors",
      body: m17l1Body,
      requires: ["m16.l1"],
      labs: [
        {
          id: "m17.l1.lab1",
          kind: "sogen",
          title: "Reach godmode cleanly",
          brief:
            "!actrace the vector set, spoof blacklists, clear debug artifacts, " +
            "raise stats through the game API and pass !godmode.",
          scenario: "tbm-ac",
          flags: [
            {
              id: "m17.l1.f1",
              sha256: F.m17l1f1,
              prompt: "!actrace lists how many detection vectors? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m17.l1.f2",
              sha256: F.m17l1f2,
              prompt:
                "The live (encrypted) stats block sits at a fixed VA. Submit it as " +
                "full 8-digit hex with 0x prefix.",
              points: 150,
            },
            {
              id: "m17.l1.f3",
              sha256: F.m17l1f3,
              prompt:
                "With every vector quiet and god-tier stats set via !setstat, " +
                "!godmode prints a secret. Submit it exactly.",
              points: 300,
            },
          ],
        },
      ],
    },
  ],
};

export const module18 = {
  id: "m18",
  title: "Linux Syscall-Table Rootkits",
  track: "linux-kernel",
  summary:
    "kfhooksy.ko rewrote one sys_call_table entry in the v86 guest; write the " +
    "kallsyms cross-checker that catches it and make the villain restore.",
  lessons: [
    {
      id: "m18.l1",
      title: "Cross-check the dispatch table",
      body: m18l1Body,
      requires: ["m17.l1"],
      labs: [
        {
          id: "m18.l1.lab1",
          kind: "linux",
          title: "Catch the hooked syscall",
          brief:
            "Resolve __NR_kill for i386, build a detector module comparing " +
            "sys_call_table entries against kallsyms symbol bounds, then call " +
            "the exported restore path.",
          scenario: "syscall-hook",
          flags: [
            {
              id: "m18.l1.f1",
              sha256: F.m18l1f1,
              prompt:
                "Submit __NR_kill's decimal syscall number on i386 (frozen ABI).",
              points: 100,
            },
            {
              id: "m18.l1.f2",
              sha256: F.m18l1f2,
              prompt:
                "Your detector prints a KFFLAG secret when it finds the entry " +
                "outside core-kernel text. Submit it exactly.",
              points: 250,
            },
            {
              id: "m18.l1.f3",
              sha256: F.m18l1f3,
              prompt:
                "After kfhooksy_restore() re-runs your clean sweep, the villain " +
                "surrenders with a final secret. Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module19 = {
  id: "m19",
  title: "Reversing the Sensor Statically",
  track: "reversing",
  summary:
    "Boundary recovery, rel32 resolution and fixture-shaped pseudocode over " +
    "kfalcon.sys — read the kill switch without executing a single byte.",
  lessons: [
    {
      id: "m19.l1",
      title: "Pseudocode from bytes",
      body: m19l1Body,
      requires: ["m18.l1"],
      labs: [
        {
          id: "m19.l1.lab1",
          kind: "windbg",
          title: "Decompile the CreationStatus store",
          brief:
            "!funcs recovers kfalcon.sys's grid; !pseudocode renders the " +
            "process callback as C. Name the count, the callback, the offset.",
          scenario: "edr-sensor",
          flags: [
            {
              id: "m19.l1.f1",
              sha256: F.m19l1f1,
              prompt:
                "!funcs kfalcon.sys recovers how many functions from the .text " +
                "grid? Submit the decimal count.",
              points: 150,
            },
            {
              id: "m19.l1.f2",
              sha256: F.m19l1f2,
              prompt:
                "Submit the registered process-callback VA (!notifyroutines) as " +
                "full 16-digit hex with 0x prefix.",
              points: 200,
            },
            {
              id: "m19.l1.f3",
              sha256: F.m19l1f3,
              prompt:
                "!pseudocode shows the CreationStatus store at CreateInfo+0x40. " +
                "Submit that field offset in DECIMAL.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module20 = {
  id: "m20",
  title: "Hooks & Integrity Monitoring",
  track: "windows-kernel",
  summary:
    "The full hook taxonomy on both sides of the verifier: PatchGuard-" +
    "compliant vs non-compliant kernel hooks with a fake mini-PatchGuard " +
    "timing lab, then the userland techniques (IAT/EAT/inline/VEH/hijack).",
  lessons: [
    {
      id: "m20.l1",
      title: "Kernel hooks: PatchGuard-compliant vs non-compliant",
      body: m20l1Body,
      requires: ["m19.l1"],
      labs: [
        {
          id: "m20.l1.lab1",
          kind: "windbg",
          title: "Beat the clock: hook, use, unhook before the sweep",
          brief:
            "A mini-PatchGuard sweeps four protected regions on the lab " +
            "clock. Install a non-compliant hook, do your read/write through " +
            "it, restore pristine bytes and cross a clean sweep — or eat a " +
            "0x109.",
          scenario: "pg-hooks",
          flags: [
            {
              id: "m20.l1.f1",
              sha256: F.m20l1f1,
              prompt:
                "Leave the hook installed across a sweep and the world " +
                "bugchecks. Submit the STOP code as a 3-digit decimal.",
              points: 100,
            },
            {
              id: "m20.l1.f2",
              sha256: F.m20l1f2,
              prompt:
                "!pgstatus lists the protected regions it re-validates every " +
                "sweep. Submit that count in decimal.",
              points: 100,
            },
            {
              id: "m20.l1.f3",
              sha256: F.m20l1f3,
              prompt:
                "Hook PsLookupProcessByProcessId, use it (!hooktest), restore " +
                "the pristine bytes and pump past one clean sweep — !pgstatus " +
                "prints a completion secret. Submit it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
    {
      id: "m20.l2",
      title: "Userland hooks: IAT, EAT, inline, VEH & thread hijack",
      body: m20l2Body,
      requires: ["m20.l1"],
      labs: [
        {
          id: "m20.l2.lab1",
          kind: "quiz",
          title: "Pick the right ring-3 technique",
          brief:
            "Reading comprehension check on the userland hook taxonomy — " +
            "then run m6/m17 for the hands-on halves.",
          scenario: null,
          flags: [
            {
              id: "m20.l2.f1",
              sha256: F.m20l2f1,
              prompt:
                "Which userland hook technique overwrites a module's Import " +
                "Address Table entries? Submit the three-letter abbreviation.",
              points: 100,
            },
            {
              id: "m20.l2.f2",
              sha256: F.m20l2f2,
              prompt:
                "Which technique leaves .text byte-for-byte pristine by " +
                "redirecting through vectored exceptions / debug registers? " +
                "Submit the three-letter abbreviation.",
              points: 100,
            },
          ],
        },
      ],
    },
  ],
};

export const module21 = {
  id: "m21",
  title: "Userland Injection",
  track: "windows-userland",
  summary:
    "Land bytes in another process two ways — a real handle with audited " +
    "access rights, or handleless via KeStackAttachProcess — and compare " +
    "what each footprint leaks to a defender.",
  lessons: [
    {
      id: "m21.l1",
      title: "Handle-based vs handleless injection",
      body: m21l1Body,
      requires: ["m20.l2"],
      labs: [
        {
          id: "m21.l1.lab1",
          kind: "compiler",
          title: "Inject both ways into kftarget.exe",
          brief:
            "Compile the starter: it opens a tracked handle against pid 888, " +
            "writes payload via ZwWriteVirtualMemory, then re-writes " +
            "handlelessly through KeStackAttachProcess. Telemetry proves " +
            "both paths.",
          scenario: "ul-inject",
          compileTask: "ul-inject",
          starterFiles: [
            { path: "driver/kfinject.c", content: INJECT_STARTER },
          ],
          flags: [
            {
              id: "m21.l1.f1",
              sha256: F.m21l1f1,
              prompt:
                "Run the compiled driver in the ul-inject world. Its DbgPrint " +
                "buffer ends with a completion secret — submit it exactly.",
              points: 200,
            },
            {
              id: "m21.l1.f2",
              sha256: F.m21l1f2,
              prompt:
                "ZwWriteVirtualMemory needs PROCESS_VM_OPERATION plus one more " +
                "access right on the handle. Submit that constant exactly as " +
                "spelled in ntddk.h.",
              points: 100,
            },
            {
              id: "m21.l1.f3",
              sha256: F.m21l1f3,
              prompt:
                "The handleless path attaches to the target. Which per-thread " +
                "structure records the attachment? Submit the field name " +
                "(one word, lowercase).",
              points: 100,
            },
          ],
        },
      ],
    },
  ],
};

export const module22 = {
  id: "m22",
  title: "Custom Hypervisors & EPT",
  track: "windows-kernel",
  summary:
    "Ring -1 architecture (VMX/VMCS/EPT) and the EPT-shadow arms race: " +
    "hidden hooks that split fetches from reads, and the dual-view, timing " +
    "and CPUID techniques that catch them.",
  lessons: [
    {
      id: "m22.l1",
      title: "Custom hypervisors — architecture from ring -1",
      body: m22l1Body,
      requires: ["m21.l1"],
      labs: [],
    },
    {
      id: "m22.l2",
      title: "EPT shadowing, EPT hooks & detection",
      body: m22l2Body,
      requires: ["m22.l1"],
      labs: [
        {
          id: "m22.l2.lab1",
          kind: "windbg",
          title: "Catch the split view: detect an EPT hook",
          brief:
            "kfhyp.sys detours PsLookupProcessByProcessId below the kernel. " +
            "Guest memory shows the detour; the host/EPT view stays pristine. " +
            "Compare translations and prove the fetch/read split.",
          scenario: "ept-shadow",
          flags: [
            {
              id: "m22.l2.f1",
              sha256: F.m22l2f1,
              prompt:
                "db the PsLookupProcessByProcessId thunk in ept-shadow: what " +
                "is the first opcode byte the GUEST sees? Submit as 0x-prefixed " +
                "two-digit hex.",
              points: 150,
            },
            {
              id: "m22.l2.f2",
              sha256: F.m22l2f2,
              prompt:
                "!eptlist reports how many shadowed ranges exist in this " +
                "world? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m22.l2.f3",
              sha256: F.m22l2f3,
              prompt:
                "!eptverify sweeps every entry for a guest/host disagreement " +
                "and prints a secret when at least one range splits. Submit " +
                "it exactly.",
              points: 250,
            },
          ],
        },
      ],
    },
  ],
};

export const module23 = {
  id: "m23",
  title: "DKOM Field Labs",
  track: "windows-kernel",
  summary:
    "Six DKOM edits that matter — hands-on labs for PPL removal and Cid " +
    "spoofing, plus the field guide to handle-pointer swaps, SMEP toggles, " +
    "CR0.WP page work and the Van1338 notify race.",
  lessons: [
    {
      id: "m23.l1",
      title: "DKOM field labs — from PPL strips to callback races",
      body: m23l1Body,
      requires: ["m22.l2"],
      labs: [
        {
          id: "m23.l1.lab1",
          kind: "windbg",
          title: "Strip lsass's PPL and open it for real",
          brief:
            "!openprocess 108 is ACCESS_DENIED while lsass wears Light|WinTcb. " +
            "Find its Protection byte, DKOM it to zero with eb, and collect " +
            "your handle.",
          scenario: "dkom-ppl",
          flags: [
            {
              id: "m23.l1.f1",
              sha256: F.m23l1f1,
              prompt:
                "Before your edit, what Protection byte does !eproc lsass show? " +
                "Submit as 0x-prefixed two-digit hex.",
              points: 100,
            },
            {
              id: "m23.l1.f2",
              sha256: F.m23l1f2,
              prompt:
                "!openprocess 108 while PPL is intact returns a familiar " +
                "failure. Submit the NTSTATUS name.",
              points: 100,
            },
            {
              id: "m23.l1.f3",
              sha256: F.m23l1f3,
              prompt:
                "Clear the byte with eb and re-run !openprocess 108 0x143a. " +
                "The first successful open prints a secret — submit it exactly.",
              points: 250,
            },
          ],
        },
        {
          id: "m23.l1.lab2",
          kind: "windbg",
          title: "Wear System's Cid: spoof kftarget's PID to 4",
          brief:
            "Overwrite kftarget.exe's UniqueProcessId with eb and watch the " +
            "process list lie — then check which records still tell the truth.",
          scenario: "dkom-pid",
          flags: [
            {
              id: "m23.l1.f4",
              sha256: F.m23l1f4,
              prompt:
                "Spoof kftarget's UniqueProcessId to 4, then run !process 0 0. " +
                "How many processes now list Cid 0004? Submit the decimal count.",
              points: 100,
            },
            {
              id: "m23.l1.f5",
              sha256: F.m23l1f5,
              prompt:
                "After the spoof, which per-thread structure still records " +
                "kftarget's true identity? Submit the field name (one word, " +
                "lowercase).",
              points: 150,
            },
          ],
        },
      ],
    },
  ],
};

export const catalog = {
  version: 5,
  modules: [module1, module2, module3, module4, module5, module6, module7, module8, module9, module10, module11, module12, module13, module14, module15, module16, module17, module18, module19, module20, module21, module22, module23],
};
