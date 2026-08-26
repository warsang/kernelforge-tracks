/**
 * rsp.mjs — GDB Remote Serial Protocol client over the v86 second UART.
 *
 * The buildroot guest runs `gdbserver /dev/ttyS1 <target>`; this module
 * speaks the wire protocol from the browser side:
 *
 *   $packet-data#checksum   with '+'/'-' acks (acked mode throughout)
 *   binary-safe ops use hex-encoded m/M memory packets; g/G register reads
 *   may contain RSP run-length encoding (`c*n` = repeat c, n = ord(n)-28).
 *
 * Transport contract (injected):
 *   send(bytes: Uint8Array)          raw bytes into the guest's ttyS1 RX
 *   onReceive(cb: (byte:number)=>void)  raw bytes from the guest's ttyS1 TX
 */

const ACK = 0x2b; // '+'
const NAK = 0x2d; // '-'
const CTRL_C = 0x03;

/** Decode RSP run-length encoding inside packet payloads. */
export function rleDecode(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "*" && i + 1 < text.length) {
      const extra = text.charCodeAt(i + 1) - 29;
      if (extra > 0 && out.length > 0) {
        out += out[out.length - 1].repeat(extra);
      }
      i++;
    } else {
      out += ch;
    }
  }
  return out;
}

export function checksum(data) {
  let sum = 0;
  for (let i = 0; i < data.length; i++) sum = (sum + data.charCodeAt(i)) & 0xff;
  return sum.toString(16).padStart(2, "0");
}

/** Build a full wire frame: $<data>#<csum> */
export function framePacket(data) {
  return "$" + data + "#" + checksum(data);
}

/**
 * @param {object} transport { send(bytes), onReceive(cb) -> void }
 * @param {{timeoutMs?: number}} [opts]
 */
export class RspClient {
  // frame reader state
  #inFrame = false;
  #hashSeen = false;
  #data = "";
  #checksumChars = "";
  constructor(transport, opts = {}) {
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    this.send = transport.send;
    /** @type {((pkt: string) => void) | null} */
    this.waiter = null;
    /** @type {string[]} */
    this.notifications = []; // async stop replies while nobody waits
    /** @type {"disconnected"|"connecting"|"idle"|"busy"} */
    this.state = "disconnected";
    this.onStateChange = null;
    transport.onReceive((byte) => this.#onByte(byte));
  }

  #setState(s) {
    this.state = s;
    this.onStateChange?.(s);
  }

  #onByte(byte) {
    const ch = String.fromCharCode(byte);

    // Outside a frame, '+'/'-' are transport acks for OUR frames.
    // Inside a frame they are protocol payload — never filtered here.
    if (!this.#inFrame) {
      if (ch === "+") return;
      if (ch === "-") {
        if (this.lastFrame) this.sendText(this.lastFrame);
        return;
      }
      if (ch !== "$") return; // stray byte
      this.#inFrame = true;
      this.#data = "";
      this.#checksumChars = "";
      return;
    }

    if (ch === "#") {
      this.#hashSeen = true;
      this.#checksumChars = "";
      return;
    }
    if (this.#hashSeen) {
      this.#checksumChars += ch;
      if (this.#checksumChars.length === 2) {
        this.#inFrame = false;
        this.#hashSeen = false;
        this.#deliver(rleDecode(this.#data));
      }
      return;
    }
    this.#data += ch;
  }

  #deliver(pkt) {
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      w(pkt);
    } else {
      // asynchronous stop notification (e.g. T05 after 'c')
      this.notifications.push(pkt);
      if (this.notifications.length > 32) this.notifications.shift();
    }
  }

  sendText(text) {
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i) & 0xff;
    this.send(bytes);
  }

  /**
   * Send a packet and wait for its response. Interrupts (0x03) bypass.
   * @returns {Promise<string>} response payload (between $ and #)
   */
  transact(data, { timeoutMs } = {}) {
    const frame = framePacket(data);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        this.#setState("idle");
        const cmd = data.split(":")[0];
        reject(new Error(
          `rsp: timeout waiting for reply to "${cmd}" (${timeoutMs ?? this.timeoutMs}ms) — ` +
          `gdbserver may not be running on ttyS1, or the serial link is broken`
        ));
      }, timeoutMs ?? this.timeoutMs);
      this.waiter = (pkt) => {
        clearTimeout(timer);
        this.#setState("idle");
        this.sendText("+"); // ack their frame
        resolve(pkt);
      };
      this.#setState("busy");
      this.lastFrame = frame;
      this.sendText(frame);
    });
  }

  /** Raw interrupt byte (Ctrl-C) — halts a running target. */
  interrupt() {
    this.send(new Uint8Array([CTRL_C]));
  }

  // ---- high-level protocol -------------------------------------------------

  /** Handshake; returns feature dict from qSupported. */
  async connect() {
    this.#setState("connecting");
    const res = await this.transact(
      "qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;QStartNoAckMode-",
    );
    const features = {};
    for (const tok of res.split(";")) {
      if (tok.includes("=")) {
        const [k, v] = tok.split("=");
        features[k] = v;
      } else if (tok.endsWith("+") || tok.endsWith("-")) {
        features[tok.slice(0, -1)] = tok.endsWith("+");
      }
    }
    await this.transact("?").catch(() => "");
    this.#setState("idle");
    return features;
  }

  async readRegisters() {
    return this.transact("g");
  }

  async writeRegisters(hexBlob) {
    return this.transact("G" + hexBlob);
  }

  async readMemory(addrHex, len) {
    const res = await this.transact(`m${addrHex},${len.toString(16)}`);
    if (res.startsWith("E")) throw new Error(`rsp read error ${res}`);
    const out = new Uint8Array(res.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(res.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  async writeMemory(addrHex, bytes) {
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    const res = await this.transact(`M${addrHex},${bytes.length.toString(16)}:${hex}`);
    if (res !== "OK") throw new Error(`rsp write error ${res}`);
    return true;
  }

  async insertBreakpoint(addrHex, kind = 1) {
    return this.transact(`Z0,${addrHex},${kind.toString(16)}`);
  }

  async removeBreakpoint(addrHex, kind = 1) {
    return this.transact(`z0,${addrHex},${kind.toString(16)}`);
  }

  /**
   * Single instruction step. There is NO direct reply to 's' — the stop
   * packet IS the response. Resolves with it.
   */
  async step() {
    this.#setState("busy");
    this.lastFrame = framePacket("s");
    this.sendText(this.lastFrame);
    return this.awaitStop();
  }

  /**
   * Continue until a stop. Resolves with the stop packet ("T05...", "S05",
   * "W.."). Same no-direct-reply rule as step().
   */
  async continueRun() {
    this.#setState("busy");
    this.lastFrame = framePacket("c");
    this.sendText(this.lastFrame);
    return this.awaitStop();
  }

  /** Wait for an async stop packet (after Ctrl-C or background events). */
  async awaitStop(timeoutMs = this.timeoutMs) {
    const pending = this.notifications.findIndex((n) => /^[TWSX]/.test(n));
    if (pending >= 0) return this.notifications.splice(pending, 1)[0];
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("rsp: no stop arrived")), timeoutMs);
      this.waiter = (pkt) => {
        clearTimeout(timer);
        this.#setState("idle");
        this.sendText("+");
        resolve(pkt);
      };
    });
  }

  /** Parse a stop packet into {signal, thread, regs:{hex:value}}. */
  parseStop(pkt) {
    const out = { raw: pkt, signal: null, thread: null, regs: {} };
    if (/^W|^X/.test(pkt)) {
      out.exited = true;
      out.code = parseInt(pkt.slice(1).split(";")[0], 16);
      return out;
    }
    const m = pkt.match(/^T([0-9a-fA-F]{2})/);
    if (!m) return out;
    out.signal = parseInt(m[1], 16);
    for (const kv of pkt.slice(3).split(";")) {
      if (!kv) continue;
      if (kv.startsWith("thread:")) out.thread = kv.slice(7);
      else if (kv.includes(":")) {
        const [k, v] = kv.split(":");
        out.regs[k] = v;
      }
    }
    return out;
  }

  detach() {
    return this.transact("D", { timeoutMs: 3000 }).catch(() => "OK");
  }
}
