// zod mirrors of shared/schemas/speedtest.config.schema.json (the settings the admin API accepts) and of the
// runner `correlation` block's connector sources (shared/schemas/runner.config.schema.json). Strict everywhere:
// an unknown key is refused, never stored. The compiled documents are validated against the real JSON Schemas by
// the node tests (worker/test/node/speedtest-compile.test.ts), which also pin these mirrors to the fixtures.
import { z } from "zod";
import { SLUG_RE } from "../util/ids";

const CTRL = /^[^\x00-\x1f\x7f]*$/;
const TEXT_CTRL = /^[^\x00-\x08\x0b-\x1f\x7f]*$/;
const IPV4 = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
const IPV4_CIDR = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(3[0-2]|[12]?[0-9])$/;
const HOST_OR_IP = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const IFACE = /^[A-Za-z0-9_.:-]{1,15}$/;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const BCP47 = /^[a-z]{2}(-[A-Za-z]{2,4})?$/;
const HEX6 = /^#[0-9A-Fa-f]{6}$/;
const ART_ID = /^art_[0-9A-HJKMNP-TV-Z]{26}$/;

const slug = z.string().regex(SLUG_RE);
const ctrl = (max: number) => z.string().max(max).regex(CTRL);
const ipv4 = z.string().regex(IPV4);
const cidr = z.string().regex(IPV4_CIDR);
const int = (min: number, max: number) => z.number().int().min(min).max(max);

/** The box's routed interface address: a plain unicast IPv4 (not 0.0.0.0, loopback, multicast or broadcast). */
export const listenIp = ipv4.refine((v) => {
  const a = Number(v.split(".")[0]);
  return v !== "0.0.0.0" && a !== 127 && a < 224;
}, "listen_ip must be a unicast address of the speedtest box (not 0.0.0.0, loopback or multicast)");

export const ServeSchema = z
  .object({
    placement: z.enum(["core", "dc", "other"]),
    hostname: z.string().regex(HOST_OR_IP),
    listen_ip: listenIp,
    require_real_client_ip: z.boolean(),
    client_subnets: z.array(cidr).max(64),
    translated_addresses: z.array(ipv4).max(64),
    port: int(1, 65535),
  })
  .partial()
  .strict();
export const ServeRequiredSchema = ServeSchema.refine((s) => s.hostname !== undefined && s.listen_ip !== undefined, "serve needs hostname and listen_ip");

export const TlsSchema = z.object({ mode: z.enum(["none", "provided"]) }).strict();
export const DnsLegSchema = z.object({ enabled: z.boolean(), zone: z.string().regex(HOST_OR_IP), port: int(1, 65535) }).partial().strict();

export const SettingsPutSchema = z
  .object({
    zones: z.array(z.object({ id: slug, name: ctrl(64) }).strict()).max(256),
    zone_labels: z.object({ subnets: z.array(z.object({ cidr, zone: slug }).strict()).max(256) }).strict(),
    branding: z
      .object({
        title: ctrl(80),
        logo_artifact: z.union([z.null(), z.string().regex(ART_ID)]),
        colors: z.object({ primary: z.string().regex(HEX6), accent: z.string().regex(HEX6), background: z.string().regex(HEX6), text: z.string().regex(HEX6) }).partial().strict(),
        languages: z.array(z.string().regex(BCP47).max(8)).max(8).refine((a) => new Set(a).size === a.length, "languages must be unique"),
        copy: z.record(z.string().regex(IDENT), ctrl(280)).refine((o) => Object.keys(o).length <= 40, "at most 40 copy entries"),
      })
      .partial()
      .strict(),
    display: z.object({ show_network_details: z.boolean() }).partial().strict(),
    targets: z.object({ down_mbps: z.number().min(0.1).max(100000), up_mbps: z.number().min(0.1).max(100000) }).partial().strict(),
    limits: z
      .object({
        tests_per_10min_per_ip: int(1, 1000),
        max_concurrent_per_ip: int(1, 100),
        max_concurrent_tests: int(1, 1000),
        max_concurrent_internet: int(1, 1000),
        bytes_local: int(1_000_000, 10_000_000_000),
        bytes_internet: int(1_000_000, 10_000_000_000),
        leg_token_ttl_s: int(10, 300),
        result_deadline_s: int(30, 900),
      })
      .partial()
      .strict(),
    internet_leg: z.object({ enabled: z.boolean(), provider: z.literal("cloudflare"), paused: z.boolean(), auto_pause_wan_util_pct: int(1, 100) }).partial().strict(),
    privacy: z.object({ retention_days: int(1, 365), scrub_after_diagnosis: z.boolean() }).partial().strict(),
    core_guard: z.object({ iface: z.string().regex(IFACE), util_pct: int(1, 100), min_bytes: int(100_000, 1_000_000_000) }).partial().strict(),
    serve: ServeRequiredSchema,
    tls: TlsSchema,
    dns_leg: DnsLegSchema,
    path: z
      .object({
        gateway: z.union([z.literal("auto"), ipv4]),
        edge: z.union([z.null(), ipv4]),
        edge1: z.union([z.null(), z.literal("auto"), ipv4]),
        note: ctrl(200),
      })
      .partial()
      .strict(),
    consent: z.object({ text: z.string().max(2000).regex(TEXT_CTRL), version: int(1, 1_000_000).optional() }).strict(),
  })
  .partial()
  .required({ consent: true })
  .strict();
export type SettingsPut = z.infer<typeof SettingsPutSchema>;

// ---- runner correlation sources (component config of a runner) --------------------------------------------------
export const CorrelationConfigSchema = z
  .object({
    enabled: z.boolean(),
    window_before_s: int(0, 3600),
    window_after_s: int(0, 3600),
    poll_interval_s: int(1, 60),
    sources: z
      .object({
        mist: z
          .object({
            sites: z.array(z.object({ site_id: ctrl(64), name: ctrl(64).optional() }).strict()).max(64),
            zone_map: z
              .array(z.object({ zone: slug, site_id: ctrl(64).optional(), ap_macs: z.array(z.string().regex(MAC)).max(256).optional(), ap_name_prefix: ctrl(64).optional() }).strict())
              .max(256),
            max_calls_per_test: int(1, 20),
            cache_ttl_s: int(1, 600),
          })
          .partial()
          .strict(),
        ec: z
          .object({
            appliances: z.array(z.object({ ne_pk: ctrl(128), hostname: ctrl(128).optional(), wan_interfaces: z.array(ctrl(32)).max(16).optional() }).strict()).max(8),
            max_flows: int(1, 50),
            wan_util: z.object({ enabled: z.boolean(), interval_s: int(5, 300) }).partial().strict(),
          })
          .partial()
          .strict(),
        syslog: z
          .object({
            listen: z.array(z.string().max(16).regex(/^(udp|tcp|tls):[0-9]{1,5}$/)).max(6).refine((a) => new Set(a).size === a.length, "listen entries must be unique"),
            bind: ipv4,
            allow: z.array(cidr).max(64),
            rate_limit_lines_per_s: int(1, 100000),
            max_line_bytes: int(128, 16384),
            ring_minutes: int(1, 60),
            // a provided syslog TLS pair has no upload route in M6: only the locally generated certificate is offered
            tls: z.object({ mode: z.literal("self_signed") }).strict(),
          })
          .partial()
          .strict(),
        // SSE has no API connector (CR-m6-spec-resolutions A.8): it is always compiled as {enabled:false}
        sse: z.object({ enabled: z.literal(false) }).strict(),
      })
      .partial()
      .strict(),
  })
  .partial()
  .strict();

/** Speedtest component config: only the host-level overrides (the rest is the site's settings). */
export const SpeedtestComponentConfigSchema = z
  .object({ collector_id: slug, serve: ServeSchema, tls: TlsSchema, dns_leg: DnsLegSchema })
  .partial()
  .strict();
