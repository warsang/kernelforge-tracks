/**
 * Serial console capture — the lab harness's ears into the v86 guest.
 *
 * The guest's kernel messages flow out the emulated 16550 UART; labs print
 * gradeable secrets with a KFFLAG magic prefix. This parser is pure JS and
 * fully unit-tested against scripted streams; the session wires it to
 * v86's serial adapter at boot.
 */

const MAGIC = "KFFLAG:";

export class SerialCapture {
  constructor() {
    this.buffer = "";
    /** @type {string[]} complete lines seen so far */
    this.lines = [];
    /** @type {{line: string, value: string}[]} */
    this.secrets = [];
    /** @type {Map<number, (line: string) => void>} */
    this.waiters = new Map();
    this.waiterSeq = 0;
    this.onLine = null;
  }

  /** Feed raw bytes (string or Uint8Array) from the UART. */
  push(chunk) {
    const text = typeof chunk === "string"
      ? chunk
      : new TextDecoder().decode(chunk);
    this.buffer += text;
    let idx;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, "");
      this.buffer = this.buffer.slice(idx + 1);
      this.line(line);
    }
  }

  line(line) {
    this.lines.push(line);

    // KFFLAG:<secret> — the lab channel; tolerate kernel log-level prefixes
    const m = line.match(/KFFLAG:\s*(.+?)\s*$/);
    if (m) this.secrets.push({ line, value: m[1] });

    if (this.onLine) try { this.onLine(line); } catch { /* listener bug */ }

    const waiters = [...this.waiters.values()];
    this.waiters.clear();
    for (const w of waiters) w(line);
  }

  /**
   * Resolve on the NEXT line to arrive (future-oriented: lab flows wait for
   * output that has not happened yet). Rejects after timeoutMs.
   */
  nextLine(timeoutMs = 30_000) {
    return new Promise((resolvePromise, rejectPromise) => {
      const id = setTimeout(() => {
        this.waiters.delete(seq);
        rejectPromise(new Error("serial: timeout waiting for line"));
      }, timeoutMs);
      const seq = this.waiterSeq++;
      this.waiters.set(seq, (line) => {
        clearTimeout(id);
        resolvePromise(line);
      });
    });
  }

  /**
   * All KFFLAG secrets matching an exact value (normalized trim+lowercase),
   * mirroring lab-runtime grading normalization.
   */
  findSecret(value) {
    const want = value.trim().toLowerCase();
    return this.secrets.filter((s) => s.value.trim().toLowerCase() === want);
  }

  get text() {
    return this.lines.join("\n");
  }
}
