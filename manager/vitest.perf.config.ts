// `npm run test:perf`: 500 hosts x 30 days of roll-ups against the local D1. Not part of `npm test` (slow).
import { defineConfig } from "vitest/config";
import { workersPlugin } from "./vitest.shared.ts";

export default defineConfig({
  plugins: [await workersPlugin()],
  test: {
    name: "perf",
    include: ["worker/test/perf/**/*.perf.test.ts"],
    setupFiles: ["./worker/test/setup.ts"],
    testTimeout: 900_000,
    hookTimeout: 900_000,
  },
});
