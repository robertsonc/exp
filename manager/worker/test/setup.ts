import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

type Bound = { DB: D1Database; TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1] };
// every test file starts from a freshly migrated (empty) local D1
const b = env as unknown as Bound;
await applyD1Migrations(b.DB, b.TEST_MIGRATIONS);
