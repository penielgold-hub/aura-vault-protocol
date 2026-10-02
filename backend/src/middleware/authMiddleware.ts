import { Request, Response, NextFunction } from 'express';
import { validateAccessToken } from '../auth.js';

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const apiKey = (req as any).apiKey as { owner: string } | undefined;
  if (apiKey) {
    (req as any).user = { sub: apiKey.owner };
    next();
    return;
  }

  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing token' });
    return;
  }
  const payload = await validateAccessToken(header.slice(7));
  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }
  (req as any).user = payload;
  next();
}
