import pg from "pg";

let pool: pg.Pool | undefined;

export function getDbPool(): pg.Pool {
  if (pool) return pool;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not configured");
  }

  pool = new pg.Pool({
    connectionString,
    max: Number.parseInt(process.env.PG_POOL_MAX ?? "10", 10),
    idleTimeoutMillis: Number.parseInt(process.env.PG_IDLE_TIMEOUT_MS ?? "30000", 10),
    connectionTimeoutMillis: Number.parseInt(process.env.PG_CONNECTION_TIMEOUT_MS ?? "5000", 10),
    ssl: process.env.PG_SSL === "true" ? { rejectUnauthorized: true } : undefined,
  });
  pool.on("error", () => {
    console.error("[db] idle PostgreSQL client error");
  });
  return pool;
}

export async function closeDbPool(): Promise<void> {
  const current = pool;
  pool = undefined;
  if (current) await current.end();
}
