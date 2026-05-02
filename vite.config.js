import { defineConfig } from "vite";

export default defineConfig({
  // Vercel serves this app from the deployment root, so absolute asset URLs are
  // the safest option for SPA rewrites and direct page refreshes.
  base: "/",
});
