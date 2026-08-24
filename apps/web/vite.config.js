import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
    headers: {
      // SharedArrayBuffer / cross-origin isolation for future unicorn backend
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
    },
    proxy: {
      // dev convenience only; production uses the wasm path
      "/api": "http://localhost:8087",
    },
  },
  build: { outDir: "dist", target: "es2022" },
  // The catalog hashes flags at module load (precomputed constants now);
  // window.process shim kept for compatibility.
  define: { "process.env": "window.process.env" },
});
