import { test } from "node:test";
import assert from "node:assert/strict";

// Node has no Worker: drive the client with an injected factory + fake worker.
class FakeWorker {
  onmessage = null;
  onerror = null;
  sent = [];
  postMessage(msg) { this.sent.push(msg); }
  terminate() { this.terminated = true; }
  /** test helper */
  emit(msg) { this.onmessage?.({ data: msg }); }
}

test("wasm client: run message, log tail, exit routing", async () => {
  const { createWasmClient } = await import("../src/backend-wasm.mjs");
  const worker = new FakeWorker();
  const client = createWasmClient(
    { file: "/root-windows/sauerbraten.exe", options: ["--headless"] },
    { workerFactory: () => worker },
  );
  client.start();

  // boot envelope shape matches the upstream worker contract
  const run = worker.sent[0];
  assert.equal(run.message, "run");
  assert.equal(run.data.file, "/root-windows/sauerbraten.exe");
  assert.deepEqual(run.data.options, ["--headless"]);
  assert.equal(run.data.wasm64, false);

  worker.emit({ message: "log", data: ["hello from the guest", "second line"] });
  assert.deepEqual(client.logLines, ["hello from the guest", "second line"]);

  assert.equal(client.exited, null);
  worker.emit({ message: "end", data: 0 });
  assert.equal(client.exited, 0);

  client.terminate();
  assert.equal(worker.terminated, true);
});

test("debugCommand degrades loudly until the FB codec lands", async () => {
  const { createWasmClient, DebuggerUnavailableError } = await import("../src/backend-wasm.mjs");
  const client = createWasmClient({ file: "x" }, { workerFactory: () => new FakeWorker() });
  client.start();
  await assert.rejects(
    () => client.debugCommand(0 /* GetRegisters */, undefined),
    DebuggerUnavailableError,
  );
});
