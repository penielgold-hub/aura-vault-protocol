import bcrypt from "bcryptjs";
import { randomBytes, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { getDbPool } from "../db.js";

export const API_KEY_SCOPES = ["read", "write", "admin"] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];

export interface ApiKeyRecord {
  id: string;
  owner: string;
  key_hash: string;
  scope: ApiKeyScope;
  expires_at: Date | null;
  revoked_at: Date | null;
}

export interface ApiKeyIdentity {
  id: string;
  owner: string;
  scope: ApiKeyScope;
}

const BCRYPT_ROUNDS = 12;
const KEY_PATTERN = /^avk_([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([0-9a-f]{64})$/i;

function db(): Pool {
  return getDbPool();
}

export function isApiKeyScope(value: unknown): value is ApiKeyScope {
  return typeof value === "string" && API_KEY_SCOPES.includes(value as ApiKeyScope);
}

export function permitsScope(actual: ApiKeyScope, required: ApiKeyScope): boolean {
  if (actual === "admin") return true;
  if (actual === "write") return required === "write" || required === "read";
  return required === "read";
}

export function parseApiKey(value: string): { id: string; secret: string } | null {
  const match = KEY_PATTERN.exec(value);
  if (!match) return null;
  return { id: match[1].toLowerCase(), secret: match[2] };
}

export async function createApiKey(input: {
  owner: string;
  scope: ApiKeyScope;
  expiresAt: Date | null;
}): Promise<{ id: string; apiKey: string; scope: ApiKeyScope; expiresAt: Date | null }> {
  const id = randomUUID();
  const secret = randomBytes(32).toString("hex");
  const apiKey = `avk_${id}.${secret}`;
  // Hash only the 256-bit secret component (bcrypt's input limit is 72 bytes).
  const keyHash = await bcrypt.hash(secret, BCRYPT_ROUNDS);

  await db().query(
    `INSERT INTO api_keys (id, owner, key_hash, scope, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [id, input.owner, keyHash, input.scope, input.expiresAt]
  );

  return { id, apiKey, scope: input.scope, expiresAt: input.expiresAt };
}

export async function findApiKey(rawKey: string): Promise<
  | { identity: ApiKeyIdentity; state: "active" }
  | { identity: Pick<ApiKeyIdentity, "id" | "owner">; state: "expired" | "revoked" }
  | null
> {
  const parsed = parseApiKey(rawKey);
  if (!parsed) return null;

  const result = await db().query<ApiKeyRecord>(
    `SELECT id, owner, key_hash, scope, expires_at, revoked_at
     FROM api_keys WHERE id = $1`,
    [parsed.id]
  );
  const record = result.rows[0];
  if (!record || !(await bcrypt.compare(parsed.secret, record.key_hash))) return null;

  const identity = { id: record.id, owner: record.owner };
  if (record.revoked_at) return { identity, state: "revoked" };
  if (record.expires_at && new Date(record.expires_at).getTime() <= Date.now()) {
    return { identity, state: "expired" };
  }
  return { identity: { ...identity, scope: record.scope }, state: "active" };
}

export async function revokeApiKey(id: string, revokedBy: string): Promise<boolean> {
  const result = await db().query<{ owner: string }>(
    `UPDATE api_keys SET revoked_at = NOW(), updated_at = NOW()
     WHERE id = $1 AND revoked_at IS NULL RETURNING owner`,
    [id]
  );
  if (result.rowCount && result.rows[0]) {
    await recordApiKeyAudit({
      event: "api_key.revoked",
      apiKeyId: id,
      owner: result.rows[0].owner,
      result: "success",
      metadata: { revokedBy },
    });
  }
  return Boolean(result.rowCount);
}

export async function recordApiKeyAudit(event: {
  event: string;
  apiKeyId?: string | null;
  owner?: string | null;
  method?: string;
  path?: string;
  statusCode?: number;
  result: string;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  try {
    await db().query(
      `INSERT INTO audit_logs
         (api_key_id, owner, event, request_method, request_path, status_code,
          result, ip_address, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
      [
        event.apiKeyId ?? null,
        event.owner ?? null,
        event.event,
        event.method ?? null,
        event.path ?? null,
        event.statusCode ?? null,
        event.result,
        event.ipAddress ?? null,
        JSON.stringify(event.metadata ?? {}),
      ]
    );
  } catch {
    // Audit failure must not leak request credentials or interrupt a response.
    console.error("[audit] failed to persist API-key event", { event: event.event });
  }
}

export function isValidApiKeyId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
