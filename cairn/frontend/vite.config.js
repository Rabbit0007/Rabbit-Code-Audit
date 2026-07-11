import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const outDir = process.env.VITE_OUT_DIR || "../src/cairn/server/static";

export default defineConfig({
  plugins: [react()],
  base: "/static/",
  build: {
    outDir,
    emptyOutDir: false,
    assetsDir: "assets",
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom"],
          "graph-core": ["cytoscape"],
          "graph-layout": ["cytoscape-dagre", "dagre"],
          icons: ["lucide-react"],
        },
      },
    },
  },
});
