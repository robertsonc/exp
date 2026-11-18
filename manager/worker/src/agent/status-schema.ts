// zod mirror of shared/schemas/status.schema.json (exp.status/1). Unknown fields are dropped (never echoed).
import { z } from "zod";

const TS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/;
const IFACE = /^[A-Za-z0-9_.:-]{1,15}$/;
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,63}$/;
const FINGERPRINT = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;
const HOSTPORT =
  /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})$/;
const HTTPS_URL = /^https:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(\/[^\s]*)?$/;

const ts = z.string().regex(TS);
const num0 = z.number().min(0);
const nnum = num0.nullable().optional();
const nint = z.number().int().min(0).nullable().optional();

export const IfaceSchema = z.object({
  name: z.string().regex(IFACE),
  mac: z.string().regex(MAC).optional(),
  state: z.enum(["up", "down", "unknown"]),
  speed_mbps: nint,
  driver: z.string().max(64).nullable().optional(),
  addrs: z.array(z.string().max(64)).max(32).optional(),
  default_route: z.boolean().optional(),
  in_use_by: z.string().regex(/^(mgmt|none|probe:[a-z0-9][a-z0-9-]{0,63})$/),
});

export const FactsSchema = z.object({
  hostname: z.string().max(253),
  machine_id: z.string().max(64).optional(),
  os: z.object({ id: z.string().max(32).optional(), version: z.string().max(32).optional() }).optional(),
  kernel: z.string().max(128).optional(),
  arch: z.enum(["amd64", "arm64"]),
  cpus: z.number().int().min(1).optional(),
  mem_mb: z.number().int().min(0).optional(),
  disk_free_mb: z.number().int().min(0).optional(),
  python: z.string().max(32).optional(),
  time: z
    .object({
      synced: z.boolean().optional(),
      source: z.string().max(64).optional(),
      offset_ms: z.number().nullable().optional(),
    })
    .optional(),
  interfaces: z.array(IfaceSchema).max(256).optional(),
});

const NetSchema = z.object({
  iface: z.string().regex(IFACE),
  role: z.string().max(32).optional(),
  link: z.enum(["up", "down", "unknown"]).optional(),
  speed_mbps: nint,
  rx_pps: nnum,
  tx_pps: nnum,
  rx_bps: nnum,
  tx_bps: nnum,
  rx_errors: nint,
  tx_errors: nint,
  rx_drops: nint,
  tx_drops: nint,
});

const DiskSchema = z.object({
  mount: z.string().max(256),
  total_gb: num0.optional(),
  used_gb: num0.optional(),
  pct: z.number().min(0).max(100).optional(),
});

export const ComponentFactsSchema = z.object({
  tls_fingerprint_sha256: z.string().regex(FINGERPRINT).optional(),
  listen: z.string().regex(HOSTPORT).optional(),
  url: z.string().max(512).regex(HTTPS_URL).optional(),
});

export const ComponentReportSchema = z.object({
  type: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/),
  id: z.string().regex(SLUG),
  version: z.string().regex(SEMVER).max(64).optional(),
  state: z.string().regex(/^[a-z][a-z_]{0,31}$/),
  health: z.enum(["ok", "degraded", "fail", "unknown"]),
  detail: z.string().max(1024).optional(),
  since: ts.nullable().optional(),
  process: z
    .object({ cpu_pct: nnum, rss_mb: nnum, restarts: nint, uptime_s: nnum })
    .optional(),
  metrics: z.record(z.string().max(64), z.unknown()).optional(),
  facts: ComponentFactsSchema.catchall(z.unknown()).optional(),
});

export const StatusSchema = z.object({
  schema: z.literal("exp.status/1"),
  agent: z.object({
    version: z.string().regex(SEMVER).max(64),
    desired_version: nint,
    applied_version: nint,
    uptime_s: num0,
    last_poll: ts.nullable().optional(),
  }),
  facts: FactsSchema,
  metrics: z.object({
    interval_s: z.number().int().min(1).optional(),
    uptime_s: nnum,
    cpu: z
      .object({ pct: nnum, iowait_pct: nnum, steal_pct: nnum, load1: nnum, load5: nnum, load15: nnum })
      .optional(),
    mem: z
      .object({
        total_mb: num0.optional(),
        used_mb: num0.optional(),
        available_mb: num0.optional(),
        pct: z.number().min(0).max(100).optional(),
        swap_used_mb: num0.optional(),
      })
      .optional(),
    disk: z.array(DiskSchema).max(64).optional(),
    disk_io: z.object({ read_kbps: nnum, write_kbps: nnum }).optional(),
    net: z.array(NetSchema).max(256).optional(),
    temp_c_max: z.number().nullable().optional(),
  }),
  components: z.array(ComponentReportSchema).max(16),
  reconcile: z
    .object({
      at: ts,
      result: z.enum(["ok", "error", "rolled_back"]),
      error: z.string().max(1024).nullable().optional(),
      duration_ms: num0.optional(),
    })
    .nullable()
    .optional(),
  events: z
    .array(z.object({ ts, level: z.enum(["info", "warn", "error"]), msg: z.string().max(1024) }))
    .max(100)
    .optional(),
});

export type StatusReport = z.infer<typeof StatusSchema>;
export type ComponentReport = z.infer<typeof ComponentReportSchema>;

export const EnrolSchema = z.object({
  token: z.string().regex(/^expe_[A-Za-z0-9_-]{43}$/),
  facts: FactsSchema,
});
