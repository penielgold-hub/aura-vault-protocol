import express from "express";
import jwt, { type SignOptions } from "jsonwebtoken";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../auth.js", () => ({ validateAccessToken: vi.fn() }));
const { evalScript } = vi.hoisted(() => ({ evalScript: vi.fn() }));
vi.mock("../redis.js", () => ({ getRedis: () => ({ eval: evalScript }) }));
vi.mock("../services/apiKeyService.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../services/apiKeyService.js")>();
  return {
    ...actual,
    findApiKey: vi.fn(),
    recordApiKeyAudit: vi.fn().mockResolvedValue(undefined),
    createApiKey: vi.fn(),
    revokeApiKey: vi.fn(),
  };
});

import { validateAccessToken } from "../auth.js";
import { apiKeyAuthentication, requireApiKeyScope } from "../middleware/apiKeyMiddleware.js";
import { authRateLimiter, userRateLimiter } from "../middleware/rateLimitMiddleware.js";
import { authenticateAdminJwt } from "../middleware/adminJwtMiddleware.js";
import { authenticate } from "../middleware/authMiddleware.js";
import { apiKeyAdminRouter } from "../routes/apiKeyAdminRoutes.js";
import { createApiKey, findApiKey, recordApiKeyAudit, revokeApiKey } from "../services/apiKeyService.js";

const ADMIN_SECRET = "test-admin-secret-that-is-at-least-32-characters-long";
const RAW_KEY = `avk_123e4567-e89b-42d3-a456-426614174000.${"a".repeat(64)}`;

function appForKeys() {
  const app = express();
  app.use(express.json());
  app.use("/api/admin/api-keys", authRateLimiter(), authenticateAdminJwt, apiKeyAdminRouter);
  app.get("/read", apiKeyAuthentication, requireApiKeyScope("read"), authenticate, userRateLimiter(), (req, res) => {
    res.json({ owner: (req as any).user.sub });
  });
  app.post("/write", apiKeyAuthentication, requireApiKeyScope("write"), authenticate, userRateLimiter(), (_req, res) => {
    res.json({ ok: true });
  });
  app.get("/admin-scope", apiKeyAuthentication, requireApiKeyScope("admin"), authenticate, userRateLimiter(), (_req, res) => {
    res.json({ ok: true });
  });
  return app;
}

function adminToken(expiresIn: SignOptions["expiresIn"] = "10m") {
  return jwt.sign({ sub: "operator-1", scope: "admin" }, ADMIN_SECRET, {
    algorithm: "HS256", issuer: "aura-vault-admin", audience: "aura-vault-admin", expiresIn,
  });
}

beforeEach(() => {
  vi.stubEnv("ADMIN_JWT_SECRET", ADMIN_SECRET);
  vi.stubEnv("JWT_SECRET", "ordinary-jwt-secret-is-different");
  vi.mocked(validateAccessToken).mockReset().mockResolvedValue(null);
  evalScript.mockReset().mockImplementation(async (_script, _keys, _key, capacity) => [1, capacity - 1, capacity, 0]);
  vi.mocked(findApiKey).mockReset();
  vi.mocked(recordApiKeyAudit).mockClear();
  vi.mocked(createApiKey).mockReset();
  vi.mocked(revokeApiKey).mockReset();
});

afterEach(() => vi.unstubAllEnvs());

describe("API-key and admin JWT middleware", () => {
  it("requires an admin JWT for creation and rejects an ordinary valid JWT with 403", async () => {
    vi.mocked(validateAccessToken).mockResolvedValue({ sub: "wallet-user", sessionId: "s" });
    const app = appForKeys();
    await request(app).post("/api/admin/api-keys").send({ scope: "read" }).expect(401);
    await request(app).post("/api/admin/api-keys").set("Authorization", "Bearer ordinary").send({ scope: "read" }).expect(403);
    expect(createApiKey).not.toHaveBeenCalled();
  });

  it("creates a key only for an admin JWT and returns its raw value in that response", async () => {
    const created = { id: "123e4567-e89b-42d3-a456-426614174000", apiKey: RAW_KEY, scope: "read" as const, expiresAt: null };
    vi.mocked(createApiKey).mockResolvedValue(created);
    const response = await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${adminToken()}`).send({ scope: "read" }).expect(201);
    expect(response.body.apiKey).toBe(RAW_KEY);
    expect(createApiKey).toHaveBeenCalledWith({ owner: "operator-1", scope: "read", expiresAt: null });
    const audit = JSON.stringify(vi.mocked(recordApiKeyAudit).mock.calls);
    expect(audit).not.toContain(RAW_KEY);
  });

  it("accepts a valid short-lived admin JWT", async () => {
    vi.mocked(createApiKey).mockResolvedValue({ id: "key-1", apiKey: RAW_KEY, scope: "read", expiresAt: null });
    await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${adminToken("10m")}`).send({ scope: "read" }).expect(201);
  });

  it("rejects an expired admin JWT", async () => {
    await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${adminToken("-1s")}`).send({ scope: "read" }).expect(401);
    expect(createApiKey).not.toHaveBeenCalled();
  });

  it("rejects an admin JWT whose lifetime exceeds the maximum", async () => {
    await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${adminToken("16m")}`).send({ scope: "read" }).expect(401);
    expect(createApiKey).not.toHaveBeenCalled();
  });

  it("rejects an admin JWT with a future iat", async () => {
    const futureIat = Math.floor(Date.now() / 1000) + 60;
    const token = jwt.sign({ sub: "operator-1", scope: "admin", iat: futureIat }, ADMIN_SECRET, {
      algorithm: "HS256", issuer: "aura-vault-admin", audience: "aura-vault-admin", expiresIn: "10m",
    });
    await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${token}`).send({ scope: "read" }).expect(401);
    expect(createApiKey).not.toHaveBeenCalled();
  });

  it("rejects normal-login requests for tier=admin as non-admin", async () => {
    vi.mocked(validateAccessToken).mockResolvedValue({ sub: "wallet-user", sessionId: "s" });
    const res = await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", "Bearer wallet-jwt").send({ scope: "admin" }).expect(403);
    expect(res.body.error).toMatch(/administrator/i);
  });

  it("authenticates a valid API key without a JWT and gives it precedence over Bearer JWT", async () => {
    vi.mocked(findApiKey).mockResolvedValue({ state: "active", identity: { id: "key-1", owner: "owner-1", scope: "read" } });
    const res = await request(appForKeys()).get("/read").set("X-API-Key", RAW_KEY)
      .set("Authorization", "Bearer invalid").expect(200);
    expect(res.body.owner).toBe("owner-1");
    expect(validateAccessToken).not.toHaveBeenCalled();
    expect(evalScript.mock.calls.map((call) => call[2])).toEqual(["rl:api-key:key-1"]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(recordApiKeyAudit).toHaveBeenCalledWith(expect.objectContaining({ event: "api_key.access", apiKeyId: "key-1" }));
    expect(JSON.stringify(vi.mocked(recordApiKeyAudit).mock.calls)).not.toContain(RAW_KEY);
  });

  it("rejects invalid, expired, and revoked keys", async () => {
    vi.mocked(findApiKey).mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ state: "expired", identity: { id: "key-2", owner: "owner" } })
      .mockResolvedValueOnce({ state: "revoked", identity: { id: "key-3", owner: "owner" } });
    const app = appForKeys();
    await request(app).get("/read").set("X-API-Key", RAW_KEY).expect(401);
    await request(app).get("/read").set("X-API-Key", RAW_KEY).expect(401);
    await request(app).get("/read").set("X-API-Key", RAW_KEY).expect(401);
    expect(recordApiKeyAudit).toHaveBeenCalledWith(expect.objectContaining({ result: "invalid" }));
    expect(recordApiKeyAudit).toHaveBeenCalledWith(expect.objectContaining({ result: "expired" }));
    expect(recordApiKeyAudit).toHaveBeenCalledWith(expect.objectContaining({ result: "revoked" }));
  });

  it("falls back to existing JWT auth when no API key is present", async () => {
    vi.mocked(validateAccessToken).mockResolvedValue({ sub: "jwt-user", sessionId: "s" });
    const res = await request(appForKeys()).get("/read").set("Authorization", "Bearer valid-user-token").expect(200);
    expect(res.body.owner).toBe("jwt-user");
    expect(findApiKey).not.toHaveBeenCalled();
    expect(evalScript.mock.calls.map((call) => call[2])).toEqual(["rl:user:jwt-user"]);
  });

  it("rate-limits admin requests before JWT validation or key creation", async () => {
    evalScript.mockResolvedValue([0, 0, 20, 45]);
    const response = await request(appForKeys()).post("/api/admin/api-keys")
      .set("Authorization", `Bearer ${adminToken()}`).send({ scope: "read" }).expect(429);
    expect(response.headers["retry-after"]).toBe("45");
    expect(evalScript.mock.calls).toHaveLength(1);
    expect(evalScript.mock.calls[0][2]).toMatch(/^rl:auth:ip:/);
    expect(createApiKey).not.toHaveBeenCalled();
    expect(validateAccessToken).not.toHaveBeenCalled();
  });

  it("rejects an exhausted API-key bucket without consuming a user bucket", async () => {
    vi.mocked(findApiKey).mockResolvedValue({ state: "active", identity: { id: "key-1", owner: "owner-1", scope: "read" } });
    evalScript.mockResolvedValue([0, 0, 120, 1]);
    const response = await request(appForKeys()).get("/read").set("X-API-Key", RAW_KEY).expect(429);
    expect(response.headers["retry-after"]).toBe("1");
    expect(evalScript.mock.calls.map((call) => call[2])).toEqual(["rl:api-key:key-1"]);
    expect(validateAccessToken).not.toHaveBeenCalled();
    expect(recordApiKeyAudit).toHaveBeenCalledWith(expect.objectContaining({ event: "api_key.access", statusCode: 429 }));
  });

  it("preserves JWT tier buckets, rate headers, and token refill decisions", async () => {
    vi.mocked(validateAccessToken).mockResolvedValue({ sub: "jwt-user", sessionId: "s", tier: "paid" });
    evalScript.mockResolvedValueOnce([1, 599, 600, 0])
      .mockResolvedValueOnce([0, 0, 600, 1])
      .mockResolvedValueOnce([1, 599, 600, 0]);
    const app = appForKeys();
    const allowed = await request(app).get("/read").set("Authorization", "Bearer valid").expect(200);
    expect(allowed.headers["x-ratelimit-limit"]).toBe("600");
    expect(allowed.headers["x-ratelimit-remaining"]).toBe("599");
    const denied = await request(app).get("/read").set("Authorization", "Bearer valid").expect(429);
    expect(denied.body).toEqual({ error: "Rate limit exceeded", tier: "paid", retryAfter: 1 });
    expect(denied.headers["retry-after"]).toBe("1");
    await request(app).get("/read").set("Authorization", "Bearer valid").expect(200);
    expect(evalScript.mock.calls.map((call) => call[2])).toEqual(Array(3).fill("rl:user:jwt-user"));
    expect(evalScript.mock.calls[0].slice(3, 5)).toEqual([600, 10]);
  });

  it("preserves fail-open behavior when Redis is unavailable", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      evalScript.mockRejectedValue(new Error("Redis unavailable"));
      vi.mocked(validateAccessToken).mockResolvedValue({ sub: "jwt-user", sessionId: "s" });
      await request(appForKeys()).get("/read").set("Authorization", "Bearer valid").expect(200);
      vi.mocked(createApiKey).mockResolvedValue({ id: "key-1", apiKey: RAW_KEY, scope: "read", expiresAt: null });
      await request(appForKeys()).post("/api/admin/api-keys")
        .set("Authorization", `Bearer ${adminToken()}`).send({ scope: "read" }).expect(201);
      expect(evalScript.mock.calls).toHaveLength(2);
    } finally {
      log.mockRestore();
    }
  });

  it("enforces read, write, and admin scopes", async () => {
    const app = appForKeys();
    vi.mocked(findApiKey).mockResolvedValue({ state: "active", identity: { id: "key-read", owner: "owner", scope: "read" } });
    await request(app).get("/read").set("X-API-Key", RAW_KEY).expect(200);
    await request(app).post("/write").set("X-API-Key", RAW_KEY).expect(403);
    vi.mocked(findApiKey).mockResolvedValue({ state: "active", identity: { id: "key-write", owner: "owner", scope: "write" } });
    await request(app).get("/read").set("X-API-Key", RAW_KEY).expect(200);
    await request(app).post("/write").set("X-API-Key", RAW_KEY).expect(200);
    await request(app).get("/admin-scope").set("X-API-Key", RAW_KEY).expect(403);
    vi.mocked(findApiKey).mockResolvedValue({ state: "active", identity: { id: "key-admin", owner: "owner", scope: "admin" } });
    await request(app).get("/admin-scope").set("X-API-Key", RAW_KEY).expect(200);
  });

  it("revokes keys through the administrator endpoint", async () => {
    vi.mocked(revokeApiKey).mockResolvedValue(true);
    const response = await request(appForKeys()).delete("/api/admin/api-keys/123e4567-e89b-42d3-a456-426614174000")
      .set("Authorization", `Bearer ${adminToken()}`).expect(200);
    expect(response.body.revoked).toBe(true);
    expect(revokeApiKey).toHaveBeenCalledWith("123e4567-e89b-42d3-a456-426614174000", "operator-1");
  });
});
