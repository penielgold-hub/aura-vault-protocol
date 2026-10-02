import type { NextFunction, Request, RequestHandler, Response } from "express";
import { findApiKey, permitsScope, recordApiKeyAudit, type ApiKeyIdentity, type ApiKeyScope } from "../services/apiKeyService.js";
import { apiKeyRateLimiter } from "./rateLimitMiddleware.js";

declare global {
  namespace Express {
    interface Request {
      apiKey?: ApiKeyIdentity;
    }
  }
}

function requestIp(req: Request): string | undefined {
  return req.ip ?? req.socket.remoteAddress;
}

function auditPath(req: Request): string {
  const route = req.route?.path;
  return route ? `${req.baseUrl}${route}` : req.baseUrl || req.path;
}

export const apiKeyAuthentication: RequestHandler = async (req, res, next) => {
  const rawKeyHeader = req.headers["x-api-key"];
  if (rawKeyHeader === undefined) {
    next();
    return;
  }
  const rawKey = typeof rawKeyHeader === "string" ? rawKeyHeader : "";

  let found: Awaited<ReturnType<typeof findApiKey>>;
  try {
    found = await findApiKey(rawKey);
  } catch {
    res.status(503).json({ error: "API-key authentication unavailable" });
    return;
  }

  if (!found) {
    await recordApiKeyAudit({
      event: "api_key.auth_rejected",
      method: req.method,
      path: auditPath(req),
      statusCode: 401,
      result: "invalid",
      ipAddress: requestIp(req),
    });
    res.status(401).json({ error: "Invalid API key" });
    return;
  }
  if (found.state !== "active") {
    await recordApiKeyAudit({
      event: `api_key.${found.state}`,
      apiKeyId: found.identity.id,
      owner: found.identity.owner,
      method: req.method,
      path: auditPath(req),
      statusCode: 401,
      result: found.state,
      ipAddress: requestIp(req),
    });
    res.status(401).json({ error: `API key ${found.state}` });
    return;
  }

  req.apiKey = found.identity;
  res.on("finish", () => {
    void recordApiKeyAudit({
      event: "api_key.access",
      apiKeyId: found.identity.id,
      owner: found.identity.owner,
      method: req.method,
      path: auditPath(req),
      statusCode: res.statusCode,
      result: res.statusCode < 400 ? "success" : "rejected",
      ipAddress: requestIp(req),
    });
  });

  apiKeyRateLimiter()(req, res, next);
};

export function requireApiKeyScope(required: ApiKeyScope): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.apiKey || permitsScope(req.apiKey.scope, required)) {
      next();
      return;
    }
    res.status(403).json({ error: "API key scope does not permit this operation" });
  };
}
