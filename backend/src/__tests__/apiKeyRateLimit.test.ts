import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { evalScript } = vi.hoisted(() => ({ evalScript: vi.fn() }));
vi.mock("../redis.js", () => ({ getRedis: () => ({ eval: evalScript }) }));

import { apiKeyRateLimiter, globalIpRateLimiter } from "../middleware/rateLimitMiddleware.js";

function rateRequest(apiKeyId?: string, ip = "192.0.2.10") {
  return {
    apiKey: apiKeyId ? { id: apiKeyId } : undefined,
    headers: {},
    socket: { remoteAddress: ip },
    path: "/resource",
  } as unknown as Request;
}

function rateResponse() {
  const response = {
    set: vi.fn().mockReturnThis(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return response as unknown as Response;
}

beforeEach(() => {
  evalScript.mockReset().mockResolvedValue([1, 119, 120, 0]);
});

describe("API-key rate limit bucket", () => {
  it("uses API-key ID and shares its bucket across changing IP addresses", async () => {
    const middleware = apiKeyRateLimiter();
    await middleware(rateRequest("key-123", "192.0.2.10"), rateResponse(), vi.fn());
    await middleware(rateRequest("key-123", "198.51.100.99"), rateResponse(), vi.fn());
    const redisKeys = evalScript.mock.calls.map((call) => call[2]);
    expect(redisKeys).toEqual(["rl:api-key:key-123", "rl:api-key:key-123"]);
  });

  it("keeps the API-key bucket separate from the existing IP bucket", async () => {
    await apiKeyRateLimiter()(rateRequest("key-123"), rateResponse(), vi.fn());
    await globalIpRateLimiter()(rateRequest(undefined, "192.0.2.10"), rateResponse(), vi.fn());
    const redisKeys = evalScript.mock.calls.map((call) => call[2]);
    expect(redisKeys).toContain("rl:api-key:key-123");
    expect(redisKeys).toContain("rl:global:ip:192.0.2.10");
    expect(redisKeys[0]).not.toBe(redisKeys[1]);
  });
});
