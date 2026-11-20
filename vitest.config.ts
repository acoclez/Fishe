// Unit tests for the pure frontend modules (`src/lib/utils/*.test.ts`): formatting,
// grading, the network-map graph. No Svelte, no browser: plain Node.
// `#lib/...` imports resolve through "imports" in package.json.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
