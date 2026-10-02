import { Request, Response, NextFunction, RequestHandler } from "express";
import { getRedis } from "../redis.js";
import { rateLimit, type Store, type RateLimitInfo } from "express-rate-limit";

export type Tier = "free" | "paid";

interface BucketConfig {
  capacity: number;    // max tokens (burst ceiling)
  refillRate: number;  // tokens added per second
}

interface BucketResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  retryAfter: number;
}

export const TIER_LIMITS: Record<Tier, BucketConfig> = {
  free: { capacity: 60, refillRate: 1 },     // 60 req/min steady-state
  paid: { capacity: 600, refillRate: 10 },    // 600 req/min steady-state
};

const IP_LIMIT: BucketConfig = { capacity: 30, refillRate: 0.5 };        // 30/min
const AUTH_LIMIT: BucketConfig = { capacity: 20, refillRate: 20 / 900 }; // 20/15 min
const API_KEY_LIMIT: BucketConfig = { capacity: 120, refillRate: 2 };    // 120/min per key

// Atomic token bucket implemented as a Lua script to eliminate race conditions.
// KEYS[1] — Redis hash key for this bucket
// ARGV[1] — capacity, ARGV[2] — refillRate (tokens/sec), ARGV[3] — now (ms), ARGV[4] — TTL (s)
// Returns: [allowed (0|1), remaining_floor, capacity_floor, retry_after_ceil]
const TOKEN_BUCKET_LUA = `
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local ttl      = tonumber(ARGV[4])

local data   = redis.call('HMGET', key, 'tokens', 'last')
local tokens = tonumber(data[1])
local last   = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  last   = now
end

local elapsed = (now - last) / 1000
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed     = 0
local retry_after = 0

if tokens >= 1 then
  tokens  = tokens - 1
  allowed = 1
else
  retry_after = math.ceil((1 - tokens) / rate)
end

redis.call('HMSET', key, 'tokens', tostring(tokens), 'last', tostring(now))
redis.call('EXPIRE', key, ttl)

return {allowed, math.floor(tokens), math.floor(capacity), retry_after}
`;

async function consumeToken(
  redisKey: string,
  config: BucketConfig
): Promise<BucketResult> {
  const now = Date.now();
  // TTL slightly longer than full-refill time so keys self-clean
  const ttl = Math.ceil(config.capacity / config.refillRate) + 60;

  const raw = (await getRedis().eval(
    TOKEN_BUCKET_LUA,
    1,
    redisKey,
    config.capacity,
    config.refillRate,
    now,
    ttl
  )) as [number, number, number, number];

  return {
    allowed: raw[0] === 1,
    remaining: raw[1],
    limit: raw[2],
    retryAfter: raw[3],
  };
}

function applyHeaders(res: Response, result: BucketResult, config: BucketConfig): void {
  const secondsToFull = Math.ceil(
    (config.capacity - result.remaining) / config.refillRate
  );
  res.set({
    "X-RateLimit-Limit": String(result.limit),
    "X-RateLimit-Remaining": String(result.remaining),
    "X-RateLimit-Reset": String(Math.floor(Date.now() / 1000) + secondsToFull),
  });
}

function clientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

// IP-based token bucket. keyPrefix isolates auth limits from global limits.
export function ipRateLimiter(
  config: BucketConfig = IP_LIMIT,
  keyPrefix = "rl:global:ip"
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const redisKey = `${keyPrefix}:${clientIp(req)}`;
    try {
      const result = await consumeToken(redisKey, config);
      applyHeaders(res, result, config);
      if (!result.allowed) {
        res.set("Retry-After", String(result.retryAfter));
        res.status(429).json({ error: "Too many requests", retryAfter: result.retryAfter });
        return;
      }
      next();
    } catch (err) {
      // Fail open on Redis errors — availability > strict enforcement
      console.error("[RateLimit] Redis error:", (err as Error).message);
      next();
    }
  };
}

// Expose the existing Redis token buckets through a middleware package modeled by
// CodeQL. The store consumes exactly one token; express-rate-limit adds no bucket.
function redisTokenBucketLimiter(
  bucket: (req: Request) => { redisKey: string; config: BucketConfig },
  skip: (req: Request) => boolean,
  error: (req: Request) => Record<string, unknown>
): RequestHandler {
  const store: Store = {
    async increment(key) {
      const { redisKey, config } = JSON.parse(key) as ReturnType<typeof bucket>;
      const result = await consumeToken(redisKey, config);
      // Translate available tokens into the hit-count API without using a fixed
      // window counter. An exhausted bucket must exceed the configured limit.
      return {
        totalHits: result.allowed ? config.capacity - result.remaining : config.capacity + 1,
        resetTime: new Date((result.allowed ? Math.floor(Date.now() / 1000) * 1000 : Date.now()) + 1000 * (result.allowed
          ? Math.ceil((config.capacity - result.remaining) / config.refillRate)
          : result.retryAfter)),
      };
    },
    decrement() {
      // Neither successful nor failed requests refund tokens.
      throw new Error("Token-bucket refunds are not supported");
    },
    async resetKey(key) {
      const { redisKey } = JSON.parse(key) as ReturnType<typeof bucket>;
      await getRedis().del(redisKey);
    },
  };
  return rateLimit({
    store,
    keyGenerator: (req) => JSON.stringify(bucket(req)),
    limit: (req) => bucket(req).config.capacity,
    skip,
    passOnStoreError: true,
    standardHeaders: false,
    legacyHeaders: true,
    handler: (req, res) => {
      const { config } = bucket(req);
      const resetTime = (req as Request & { rateLimit: RateLimitInfo }).rateLimit.resetTime!;
      const retryAfter = Math.max(1, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
      // Preserve the token-bucket full-refill reset header on denied requests.
      res.set("X-RateLimit-Reset", String(Math.floor(Date.now() / 1000) + Math.ceil(config.capacity / config.refillRate)));
      res.set("Retry-After", String(retryAfter));
      res.status(429).json({ ...error(req), retryAfter });
    },
  });
}

// Per-user tiered limiter. Must run after authenticate sets req.user.
export function userRateLimiter(): RequestHandler {
  return redisTokenBucketLimiter(
    (req) => {
      const user = (req as any).user as { sub: string; tier?: Tier };
      const tier = user.tier ?? "free";
      return { redisKey: `rl:user:${user.sub}`, config: TIER_LIMITS[tier] ?? TIER_LIMITS.free };
    },
    // apiKeyAuthentication already consumes the independent per-key bucket.
    (req) => Boolean(req.apiKey) || !(req as any).user,
    (req) => ({ error: "Rate limit exceeded", tier: (req as any).user.tier ?? "free" })
  );
}

// Per-key token bucket. It is independent of the shared IP and JWT user buckets.
export function apiKeyRateLimiter(): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const identity = (req as any).apiKey as { id: string } | undefined;
    if (!identity) { next(); return; }

    try {
      const result = await consumeToken(`rl:api-key:${identity.id}`, API_KEY_LIMIT);
      applyHeaders(res, result, API_KEY_LIMIT);
      if (!result.allowed) {
        res.set("Retry-After", String(result.retryAfter));
        res.status(429).json({ error: "API key rate limit exceeded", retryAfter: result.retryAfter });
        return;
      }
      next();
    } catch (err) {
      console.error("[RateLimit] Redis error:", (err as Error).message);
      next();
    }
  };
}

// Tight IP-based limiter for auth endpoints (20 req / 15 min).
export function authRateLimiter(): RequestHandler {
  return redisTokenBucketLimiter(
    (req) => ({ redisKey: `rl:auth:ip:${clientIp(req)}`, config: AUTH_LIMIT }),
    () => false,
    () => ({ error: "Too many requests" })
  );
}

// Global IP limiter suitable for use as app.use(), with an optional path exclusion list.
export function globalIpRateLimiter(excludePaths: string[] = []): RequestHandler {
  const limiter = ipRateLimiter();
  return (req: Request, res: Response, next: NextFunction): void => {
    if (excludePaths.includes(req.path)) { next(); return; }
    limiter(req, res, next);
  };
}
