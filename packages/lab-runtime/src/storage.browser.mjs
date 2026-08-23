/**
 * Browser storage adapter (IndexedDB via idb-keyval).
 * Kept separate from core logic so tests run in plain Node.
 */

import { createStore, get, set } from "idb-keyval";

let store;

function getStore() {
  if (!store) store = createStore("kernelforge", "progress");
  return store;
}

export async function loadProgress() {
  return (await get("progress", getStore())) ?? null;
}

export async function saveProgress(p) {
  await set("progress", p, getStore());
}
