import { defineConfig } from "vitest/config";
import { workersPlugin } from "./vitest.shared.ts";

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [await workersPlugin()],
        test: {
          name: "workers",
          include: ["worker/test/workers/**/*.test.ts"],
          setupFiles: ["./worker/test/setup.ts"],
        },
      },
      {
        test: {
          name: "node",
          environment: "node",
          include: ["worker/test/node/**/*.test.ts"],
        },
      },
    ],
  },
});
