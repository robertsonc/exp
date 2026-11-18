// Worker bindings and per-request variables.

export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  DB: D1Database;
  ARTIFACTS: R2Bucket;
  ASSETS?: Fetcher;
  RL_ENROL: RateLimiter;
  RL_AGENT: RateLimiter;
  RL_ADMIN: RateLimiter;
  // vars
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  EXP_OWNER_EMAIL: string;
  RELEASE_PUBKEY_PEM: string;
  RELEASES_REPO: string;
  ORG_NAME: string;
  MANAGER_URL?: string;
  // secrets
  EXP_MASTER_KEY?: string;
  GITHUB_TOKEN?: string;
  /** optional var: days to keep audit events (default 365, minimum 30) */
  AUDIT_RETENTION_DAYS?: string;
}

export type Role = "owner" | "admin" | "operator" | "viewer";

export interface AdminIdentity {
  email: string;
  role: Role;
}

export interface AgentIdentity {
  hostId: string;
}

export interface AgentAuth extends AgentIdentity {
  /** version of the host's current desired document (null: none compiled yet) */
  desiredVersion: number | null;
}

export type AppBindings = { Bindings: Env; Variables: { admin?: AdminIdentity; agent?: AgentAuth; ip: string } };

export const DEFAULT_ORG = "default";
