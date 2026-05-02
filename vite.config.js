import { defineConfig } from "vite";

export default defineConfig({
  // Relative asset paths keep the production build working on Vercel, local
  // static previews, and GitHub Pages-style subpath deployments.
  base: "./",
});
