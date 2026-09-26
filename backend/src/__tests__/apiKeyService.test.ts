import bcrypt from "bcryptjs";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { query } = vi.hoisted(() => ({ query: vi.fn() }));
vi.mock("../db.js", () => ({ getDbPool: () => ({ query }) }));

import { createApiKey, findApiKey, recordApiKeyAudit, revokeApiKey } from "../services/apiKeyService.js";

beforeEach(() => query.mockReset());

describe("API-key persistence", () => {
  it("returns a secure random key once and stores only a bcrypt hash", async () => {
    query.mockResolvedValue({ rows: [], rowCount: 1 });
    const created = await createApiKey({ owner: "wallet-owner", scope: "write", expiresAt: null });
    expect(created.apiKey).toMatch(/^avk_[0-9a-f-]+\.[0-9a-f]{64}$/i);
    const params = query.mock.calls[0][1] as unknown[];
    const storedHash = String(params[2]);
    expect(storedHash).toMatch(/^\$2[aby]\$/);
    expect(created.apiKey).not.toContain(storedHash);
    const secret = created.apiKey.split(".")[1];
    expect(await bcrypt.compare(secret, storedHash)).toBe(true);
    expect(params).not.toContain(created.apiKey);
    expect(params).not.toContain(secret);
  });

  it("looks up the public key id, verifies only its secret, and detects expiry/revocation", async () => {
    const secret = "b".repeat(64);
    const hash = await bcrypt.hash(secret, 4);
    query.mockResolvedValueOnce({ rows: [{
      id: "123e4567-e89b-42d3-a456-426614174000", owner: "owner", key_hash: hash,
      scope: "read", expires_at: null, revoked_at: null,
    }] });
    const active = await findApiKey(`avk_123e4567-e89b-42d3-a456-426614174000.${secret}`);
    expect(active).toEqual({ state: "active", identity: { id: "123e4567-e89b-42d3-a456-426614174000", owner: "owner", scope: "read" } });

    query.mockResolvedValueOnce({ rows: [{
      id: "123e4567-e89b-42d3-a456-426614174000", owner: "owner", key_hash: hash,
      scope: "read", expires_at: null, revoked_at: new Date(),
    }] });
    expect(await findApiKey(`avk_123e4567-e89b-42d3-a456-426614174000.${secret}`)).toMatchObject({ state: "revoked" });

    query.mockResolvedValueOnce({ rows: [{
      id: "123e4567-e89b-42d3-a456-426614174000", owner: "owner", key_hash: hash,
      scope: "read", expires_at: new Date(Date.now() - 1000), revoked_at: null,
    }] });
    expect(await findApiKey(`avk_123e4567-e89b-42d3-a456-426614174000.${secret}`)).toMatchObject({ state: "expired" });
  });

  it("uses parameterized SQL for revoke and audit without including a raw key", async () => {
    query.mockResolvedValueOnce({ rows: [{ owner: "key-owner" }], rowCount: 1 });
    query.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    expect(await revokeApiKey("key-id", "operator")).toBe(true);
    expect(query.mock.calls[0][0]).toContain("WHERE id = $1");
    expect(query.mock.calls[0][1]).toEqual(["key-id"]);

    await recordApiKeyAudit({ event: "api_key.access", apiKeyId: "key-id", owner: "owner", result: "success" });
    expect(query.mock.calls[2][0]).toContain("VALUES ($1, $2, $3");
    expect(query.mock.calls[2][1]).toContain("api_key.access");
    expect(JSON.stringify(query.mock.calls)).not.toMatch(/avk_[0-9a-f-]+\.[0-9a-f]{64}/i);
  });
});
