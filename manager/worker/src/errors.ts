// Error envelope (01-contracts.md section 1): {"error":{"code","message","details"}}. No stack traces.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown>;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    code: string,
    message: string,
    details: Record<string, unknown> = {},
    headers: Record<string, string> = {},
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.headers = headers;
  }
}

export function errorBody(code: string, message: string, details: Record<string, unknown> = {}) {
  return { error: { code, message, details } };
}

export function errorResponse(e: ApiError): Response {
  return new Response(JSON.stringify(errorBody(e.code, e.message, e.details)), {
    status: e.status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...e.headers },
  });
}

export const unauthenticated = () => new ApiError(401, "unauthenticated", "unauthenticated");
export const invalidToken = () =>
  new ApiError(401, "invalid_token", "missing or invalid token", {}, { "www-authenticate": "Bearer" });
export const notFound = (what = "not found") => new ApiError(404, "not_found", what);
export const forbidden = (message = "forbidden") => new ApiError(403, "forbidden", message);
export const invalidRequest = (message: string, details: Record<string, unknown> = {}) =>
  new ApiError(400, "invalid_request", message, details);
export const rateLimited = (retryAfter = 60) =>
  new ApiError(429, "rate_limited", "rate limited", {}, { "retry-after": String(retryAfter) });
export const unavailable = (message = "service unavailable") =>
  new ApiError(503, "unavailable", message, {}, { "retry-after": "30" });

/** Thrown by the secret layer when the server is misconfigured (never carries key material). */
export class ConfigError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
