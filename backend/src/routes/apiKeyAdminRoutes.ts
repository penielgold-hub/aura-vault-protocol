import { Router, type Request, type Response } from "express";
import { createApiKey, isApiKeyScope, isValidApiKeyId, recordApiKeyAudit, revokeApiKey } from "../services/apiKeyService.js";

export const apiKeyAdminRouter = Router();

apiKeyAdminRouter.post("/", async (req: Request, res: Response): Promise<void> => {
  const user = (req as any).user as { sub?: string } | undefined;
  if (!user?.sub) {
    res.status(401).json({ error: "Administrator JWT required" });
    return;
  }
  const scope = req.body?.scope;
  if (!isApiKeyScope(scope)) {
    res.status(400).json({ error: "scope must be read, write, or admin" });
    return;
  }

  let expiresAt: Date | null = null;
  if (req.body?.expiresAt !== undefined && req.body.expiresAt !== null) {
    if (typeof req.body.expiresAt !== "string") {
      res.status(400).json({ error: "expiresAt must be an ISO date string or null" });
      return;
    }
    expiresAt = new Date(req.body.expiresAt);
    if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
      res.status(400).json({ error: "expiresAt must be a future date" });
      return;
    }
  }

  try {
    const created = await createApiKey({ owner: user.sub, scope, expiresAt });
    await recordApiKeyAudit({
      event: "api_key.created",
      apiKeyId: created.id,
      owner: user.sub,
      method: req.method,
      path: req.path,
      statusCode: 201,
      result: "success",
      ipAddress: req.ip,
      metadata: { scope, expiresAt: expiresAt?.toISOString() ?? null },
    });
    // This is the sole response containing the secret; it is never persisted or logged.
    res.status(201).json({ id: created.id, apiKey: created.apiKey, scope, expiresAt });
  } catch {
    res.status(503).json({ error: "Unable to create API key" });
  }
});

apiKeyAdminRouter.delete("/:id", async (req: Request, res: Response): Promise<void> => {
  const user = (req as any).user as { sub?: string } | undefined;
  if (!user?.sub) {
    res.status(401).json({ error: "Administrator JWT required" });
    return;
  }
  const id = String(req.params.id);
  if (!isValidApiKeyId(id)) {
    res.status(400).json({ error: "Invalid API key id" });
    return;
  }
  try {
    const revoked = await revokeApiKey(id, user.sub);
    if (!revoked) {
      res.status(404).json({ error: "API key not found or already revoked" });
      return;
    }
    res.json({ id, revoked: true });
  } catch {
    res.status(503).json({ error: "Unable to revoke API key" });
  }
});
