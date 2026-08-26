/**
 * autoirp.mjs — speakeasy-class automatic IRP driving for the analyzer.
 *
 * After DriverEntry succeeds, most of a driver's behavior hides behind
 * MajorFunction. This module:
 *   1. sends IRP_MJ_CREATE / IRP_MJ_CLOSE (the lifecycle every driver has),
 *   2. harvests candidate CTL_CODEs from .text by decoding immediate-bearing
 *      instructions (mov/push/cmp/arith imm32 forms) and keeping dwords whose
 *      DeviceType/Access/Function/Method bitfields look like real IOCTL codes,
 *   3. synthesizes METHOD_BUFFERED requests against each harvested code with
 *      a few canned input patterns, reading back IoStatus/SystemBuffer.
 *
 * Deterministic: no randomness, stable ordering, capped work.
 */

import { IRP_MJ } from "@kernelforge/ntsim/src/devices.mjs";

// ---------------------------------------------------------------- harvesting

/** Decode-friendly scan: sliding imm32 window over executable sections.
 *
 * Rather than fully decoding x64, sweep every dword-aligned-to-byte offset
 * and keep dwords passing the CTL_CODE bitfield filter — the same
 * constant-harvesting trick speakeasy-class fuzzers use. False positives are
 * cheap: they just become one extra probed request.
 */
export function harvestCtlCodes(imageBytes, pe, opts = {}) {
  const cap = opts.maxCodes ?? 32;
  const out = [];
  const seen = new Set();

  const exec = pe.sections.filter((s) => s.chars & 0x20000000); // IMAGE_SCN_MEM_EXECUTE
  const spans = (exec.length ? exec : pe.sections).map((s) => ({
    start: s.rva,
    bytes: imageBytes.subarray(
      s.rawPtr,
      s.rawPtr + Math.min(s.virtualSize || s.rawSize, opts.maxScanBytes ?? 0x40000),
    ),
  }));

  for (const { start, bytes } of spans) {
    for (let i = 0; i + 4 <= bytes.length; i++) {
      const v =
        (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0;
      if (!looksLikeCtlCode(v)) continue;
      if (seen.has(v)) continue;
      seen.add(v);
      out.push({ value: v, rva: BigInt(start + i), major: IRP_MJ.DEVICE_CONTROL });
      if (out.length >= cap) return out.sort((a, b) => a.value - b.value);
    }
  }
  return out.sort((a, b) => a.value - b.value);
}

/** CTL_CODE(DeviceType, Function, Method, Access) bit layout filter. */
export function looksLikeCtlCode(v) {
  const method = v & 3;
  const func = (v >>> 2) & 0xfff;
  const access = (v >>> 14) & 3;
  const devType = (v >>> 16) & 0xffff;
  if (method !== 0 && method !== 3) return false; // BUFFERED or NEITHER only
  if (func < 0x800) return false; // custom range per winioctl.h
  if (devType === 0 || devType > 0x8000) return false;
  if (v === 0xffffffff) return false;
  return true;
}

// --------------------------------------------------------------- auto-drive

function inputPatterns(opts) {
  if (opts.inputPatterns?.length) return opts.inputPatterns;
  return [
    new Uint8Array(16),
    Uint8Array.from({ length: 16 }, (_, i) => 0xff),
    Uint8Array.from({ length: 16 }, (_, i) => i),
  ];
}

/**
 * Drive lifecycle majors + harvested DEVICE_CONTROL codes through sendIrp.
 * @param {object} kernel NtKernel
 * @param {object} device device record (createDeviceObject / driver's own)
 * @param {{harvested?:Array<{value:number}>, maxCodes?:number, inputPatterns?:Uint8Array[], sendIrp:Function}} cfg
 * @returns {Promise<Array<object>>} per-IRP results in drive order
 */
export async function autoDriveIrps(kernel, device, cfg) {
  const sendIrp = cfg.sendIrp;
  const onPhase = cfg.onPhase ?? (() => {});
  const results = [];
  const push = async (spec, phase) => {
    if (phase) onPhase(phase);
    const r = await sendIrp(kernel, device, spec);
    results.push({
      ...r,
      outputHex: r.outputHex ?? "",
      error: r.error ? String(r.error.message ?? r.error) : undefined,
    });
    return r;
  };

  // lifecycle
  await push({ major: IRP_MJ.CREATE }, "irp MJ_CREATE");
  if (results.at(-1).status !== "ok") return results;

  for (const code of (cfg.harvested ?? []).slice(0, cfg.maxCodes ?? 32)) {
    let hardFail = false;
    let i = 0;
    for (const input of inputPatterns(cfg)) {
      const r = await push({
        major: IRP_MJ.DEVICE_CONTROL,
        ioctl: BigInt(code.value),
        input,
        outputLen: cfg.outputLen ?? 64,
      }, `ioctl 0x${code.value.toString(16)} #${++i}`);
      if (r.status !== "ok") { hardFail = true; break; }
      if (kernel.bugcheck || kernel.crash) return results;
    }
    if (hardFail) break;
  }

  await push({ major: IRP_MJ.CLOSE }, "irp MJ_CLOSE");
  return results;
}
