import { defineConfig } from "vite";

export default defineConfig({
  server: { port: 5173, strictPort: true },
  build: { outDir: "dist", target: "es2022" },
  // The catalog hashes flags from process.env at module load; index.html
  // installs a window.process shim before any module runs.
  define: { "process.env": "window.process.env" },
});
