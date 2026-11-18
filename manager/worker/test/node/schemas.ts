// Validates compiled documents against the frozen JSON Schemas in shared/schemas (WP-0).
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const dir = resolve(fileURLToPath(new URL(".", import.meta.url)), "../../../../shared/schemas");

let ajv: Ajv2020 | null = null;
function get(): Ajv2020 {
  if (ajv) return ajv;
  const a = new Ajv2020({ strict: false, allErrors: true });
  addFormats.default(a);
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".schema.json"))) {
    a.addSchema(JSON.parse(readFileSync(join(dir, f), "utf8")), f);
  }
  ajv = a;
  return a;
}

export function validateAgainst(schemaFile: string, doc: unknown): string[] {
  const v = get().getSchema(schemaFile);
  if (!v) throw new Error(`schema ${schemaFile} not found`);
  return v(doc) ? [] : (v.errors ?? []).slice(0, 10).map((e) => `${e.instancePath} ${e.message}`);
}

export const loadSharedJson = (rel: string): unknown => JSON.parse(readFileSync(resolve(dir, "..", rel), "utf8"));
