import jwt from "jsonwebtoken";
import type { RequestHandler } from "express";
import { validateAccessToken } from "../auth.js";

const ADMIN_ISSUER = "aura-vault-admin";
const ADMIN_AUDIENCE = "aura-vault-admin";
// Match the documented 15-minute access-token lifetime.
export const ADMIN_JWT_MAX_LIFETIME_SECONDS = 15 * 60;

export const authenticateAdminJwt: RequestHandler = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Administrator JWT required" });
    return;
  }

  const token = header.slice(7);
  const secret = process.env.ADMIN_JWT_SECRET;
  if (!secret || secret.length < 32 || secret === process.env.JWT_SECRET) {
    res.status(503).json({ error: "Administrator JWT verification is not configured" });
    return;
  }

  try {
    const claims = jwt.verify(token, secret, {
      algorithms: ["HS256"],
      issuer: ADMIN_ISSUER,
      audience: ADMIN_AUDIENCE,
    });
    if (
      typeof claims === "object" && claims !== null &&
      claims.scope === "admin" && typeof claims.sub === "string" && claims.sub.length > 0 &&
      typeof claims.iat === "number" && typeof claims.exp === "number" &&
      claims.iat <= Math.floor(Date.now() / 1000) &&
      claims.exp > claims.iat && claims.exp - claims.iat <= ADMIN_JWT_MAX_LIFETIME_SECONDS
    ) {
      (req as any).user = claims;
      next();
      return;
    }
  } catch {
    // Distinguish a valid ordinary user JWT (403) from invalid credentials (401).
  }

  const ordinaryJwt = await validateAccessToken(token).catch(() => null);
  if (ordinaryJwt) {
    res.status(403).json({ error: "Administrator access required" });
    return;
  }
  res.status(401).json({ error: "Invalid or expired administrator JWT" });
};
